package io.mosip.testrig.apirig.utils;

import org.apache.log4j.Logger;
import org.json.JSONObject;
import org.testng.SkipException;

import io.mosip.testrig.apirig.dto.TestCaseDTO;
import io.mosip.testrig.apirig.testrunner.BaseTestCase;
import io.mosip.testrig.apirig.testrunner.MockSMTPListener;

public class MimotoUtil extends AdminTestUtil {

	private static final Logger logger = Logger.getLogger(MimotoUtil.class);
	public static final String SEND_OTP_ENDPOINT = "mimoto/req/";
	public static final String MIMOTO_CREDENTIAL_STATUS = "Mimoto_CredentialsStatus_";
	public static final String OTP_FEATURE_NOT_SUPPORTED = "OTP feature not supported. Hence skipping the testcase";
	
	
	private static String otpEnabled = "true";

	public static String isOTPEnabled() {
		String value = getValueFromMimotoActuator("/mimoto-default.properties", "mosip.otp.download.enable");
		if (value != null && !(value.isBlank()))
			otpEnabled = value;
		return otpEnabled;
	}
	
	public static String isTestCaseValidForExecution(TestCaseDTO testCaseDTO) {
		String testCaseName = testCaseDTO.getTestCaseName();
		if (isOTPEnabled().equals("false") && (testCaseDTO.getEndPoint().contains(SEND_OTP_ENDPOINT)
				|| testCaseDTO.getInput().contains(SEND_OTP_ENDPOINT)
				|| testCaseName.startsWith(MIMOTO_CREDENTIAL_STATUS) || testCaseName.contains("_vid")
				|| testCaseName.contains("_VID"))) {
			throw new SkipException(OTP_FEATURE_NOT_SUPPORTED);
		}
		return testCaseName;
	}
	
	public static String getOTPFromSMTP(String inputJson, TestCaseDTO testCaseDTO) {
		String testCaseName = testCaseDTO.getTestCaseName();
		JSONObject request = new JSONObject(inputJson);
		String emailId = null;
		String otp = null;
		
		
		if (testCaseName.contains("ESignet_AuthenticateUser") && request.has(GlobalConstants.REQUEST)) {
			if (request.getJSONObject(GlobalConstants.REQUEST).has(GlobalConstants.CHALLENGELIST)) {
				if (request.getJSONObject(GlobalConstants.REQUEST).getJSONArray(GlobalConstants.CHALLENGELIST)
						.length() > 0) {
					if (request.getJSONObject(GlobalConstants.REQUEST).getJSONArray(GlobalConstants.CHALLENGELIST)
							.getJSONObject(0).has(GlobalConstants.CHALLENGE)) {
						if (request.getJSONObject(GlobalConstants.REQUEST).getJSONArray(GlobalConstants.CHALLENGELIST)
								.getJSONObject(0).getString(GlobalConstants.CHALLENGE)
								.endsWith(GlobalConstants.MAILINATOR_COM)
								|| request.getJSONObject(GlobalConstants.REQUEST)
										.getJSONArray(GlobalConstants.CHALLENGELIST).getJSONObject(0)
										.getString(GlobalConstants.CHALLENGE).endsWith(GlobalConstants.MOSIP_NET)
								|| request.getJSONObject(GlobalConstants.REQUEST)
										.getJSONArray(GlobalConstants.CHALLENGELIST).getJSONObject(0)
										.getString(GlobalConstants.CHALLENGE).endsWith(GlobalConstants.OTP_AS_PHONE)) {
							emailId = request.getJSONObject(GlobalConstants.REQUEST)
									.getJSONArray(GlobalConstants.CHALLENGELIST).getJSONObject(0)
									.getString(GlobalConstants.CHALLENGE);
							if (emailId.endsWith(GlobalConstants.OTP_AS_PHONE))
								emailId = emailId.replace(GlobalConstants.OTP_AS_PHONE, "");
							logger.info(emailId);
							otp = MockSMTPListener.getOtp(emailId);
							request.getJSONObject(GlobalConstants.REQUEST).getJSONArray(GlobalConstants.CHALLENGELIST)
									.getJSONObject(0).put(GlobalConstants.CHALLENGE, otp);
							inputJson = request.toString();
							return inputJson;
						}
					}
				}
			}
		}
		
		return inputJson;
	}
	
}