package io.mosip.testrig.apirig.utils;

import org.apache.log4j.Logger;
import org.json.JSONObject;
import org.testng.SkipException;

import io.mosip.testrig.apirig.dto.TestCaseDTO;
import io.mosip.testrig.apirig.testrunner.OTPListener;

public class MimotoUtil extends AdminTestUtil {

	private static final Logger logger = Logger.getLogger(MimotoUtil.class);
	private static String otpEnabled = "true";

	public static String isOTPEnabled() {
		String value = getValueFromMimotoActuator("/mimoto-default.properties", "mosip.otp.download.enable").isBlank()
				? System.getenv("isOTPEnabled")
				: getValueFromMimotoActuator("/mimoto-default.properties", "mosip.otp.download.enable");
		if (value != null && !(value.isBlank()))
			otpEnabled = value;
		logger.info("OTP Enabled value: " + otpEnabled);
		return otpEnabled;
	}
	
	public static TestCaseDTO changeContextURLByFlag(TestCaseDTO testCaseDTO) {
		if (!(System.getenv("useOldContextURL") == null) && !(System.getenv("useOldContextURL").isBlank())
				&& System.getenv("useOldContextURL").equalsIgnoreCase("true")) {
			if (testCaseDTO.getEndPoint().contains("/v1/mimoto/")) {
				testCaseDTO.setEndPoint(testCaseDTO.getEndPoint().replace("/v1/mimoto/", "/residentmobileapp/"));
			}
			if (testCaseDTO.getInput().contains("/v1/mimoto/")) {
				testCaseDTO.setInput(testCaseDTO.getInput().replace("/v1/mimoto/", "/residentmobileapp/"));
			}
		}

		return testCaseDTO;
	}
	
	public static TestCaseDTO isTestCaseValidForTheExecution(TestCaseDTO testCaseDTO) {
		String testCaseName = testCaseDTO.getTestCaseName();
		String endpoint = testCaseDTO.getEndPoint();
		String inputJson = testCaseDTO.getInput();
		
		if (isOTPEnabled().equals("false")) {
			if (testCaseDTO.getEndPoint().contains(GlobalConstants.SEND_OTP_ENDPOINT)
					|| testCaseDTO.getInput().contains(GlobalConstants.SEND_OTP_ENDPOINT)
					|| testCaseName.startsWith(GlobalConstants.MIMOTO_CREDENTIAL_STATUS)
					|| (testCaseName.startsWith("Mimoto_Generate_") && endpoint.contains("/v1/mimoto/vid"))) {
				throw new SkipException(GlobalConstants.OTP_FEATURE_NOT_SUPPORTED);
			}
			
			if (inputJson.contains("_vid$")) {
				inputJson = inputJson.replace("_vid$", "_VID$");
				testCaseDTO.setInput(inputJson);
			}
		}
		if (isOTPEnabled().equals("true") && endpoint.contains("/idrepository/v1/vid")) {
			throw new SkipException(GlobalConstants.FEATURE_NOT_SUPPORTED_MESSAGE);
		}
		
		if (SkipTestCaseHandler.isTestCaseInSkippedList(testCaseName)) {
			throw new SkipException(GlobalConstants.KNOWN_ISSUES);
		}
		return testCaseDTO;
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
							otp = OTPListener.getOtp(emailId);
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
	
	public static String getClientIdSection(String baseURL) {
		if (baseURL.contains("esignet-mosipid")) {
			return "mimoto.oidc.mosipid.partner.clientid";
		}
		if (baseURL.contains("esignet-insurance")) {
			return "mimoto.oidc.sunbird.partner.clientid";
		}

		return "mimoto.oidc.partner.clientid";
	}
}