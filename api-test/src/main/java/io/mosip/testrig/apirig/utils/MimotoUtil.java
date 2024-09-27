package io.mosip.testrig.apirig.utils;

import org.apache.log4j.Logger;
import org.testng.SkipException;

import io.mosip.testrig.apirig.dto.TestCaseDTO;

public class MimotoUtil extends AdminTestUtil {

	private static final Logger logger = Logger.getLogger(MimotoUtil.class);
	public static final String SEND_OTP_ENDPOINT = "mimoto/req/";
	public static final String MIMOTO_CREDENTIAL_STATUS = "Mimoto_CredentialsStatus_";
	public static final String OTP_FEATURE_NOT_SUPPORTED = "OTP feature not supported. Hence skipping the testcase";
	
	
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
	
	public static String isTestCaseValidForExecution(TestCaseDTO testCaseDTO) {
		String testCaseName = testCaseDTO.getTestCaseName();
		if (isOTPEnabled().equals("false") && (testCaseDTO.getEndPoint().contains(SEND_OTP_ENDPOINT)
				|| testCaseDTO.getInput().contains(SEND_OTP_ENDPOINT)
				|| testCaseName.startsWith(MIMOTO_CREDENTIAL_STATUS) || testCaseName.contains("_vid"))) {
			throw new SkipException(OTP_FEATURE_NOT_SUPPORTED);
		}
		return testCaseName;
	}
	
}