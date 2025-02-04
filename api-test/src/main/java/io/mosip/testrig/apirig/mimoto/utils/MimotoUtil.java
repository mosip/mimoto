package io.mosip.testrig.apirig.mimoto.utils;

import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.HashMap;

import org.apache.log4j.Logger;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.json.JSONObject;
import org.testng.SkipException;

import io.mosip.testrig.apirig.dataprovider.BiometricDataProvider;
import io.mosip.testrig.apirig.dto.TestCaseDTO;
import io.mosip.testrig.apirig.mimoto.testrunner.MosipTestRunner;
import io.mosip.testrig.apirig.testrunner.OTPListener;
import io.mosip.testrig.apirig.utils.AdminTestUtil;
import io.mosip.testrig.apirig.utils.GlobalConstants;
import io.mosip.testrig.apirig.utils.SkipTestCaseHandler;

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
		
		int indexof = testCaseName.indexOf("_");
		String modifiedTestCaseName = testCaseName.substring(indexof + 1);
		
		addTestCaseDetailsToMap(modifiedTestCaseName, testCaseDTO.getUniqueIdentifier());
		
		
		String endpoint = testCaseDTO.getEndPoint();
		String inputJson = testCaseDTO.getInput();
		
		if (MosipTestRunner.skipAll == true) {
			throw new SkipException(GlobalConstants.PRE_REQUISITE_FAILED_MESSAGE);
		}
		
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
			return MimotoConfigManager.getproperty("mimoto-oidc-mosipid-partner-clientid");
		}
		if (baseURL.contains("esignet-insurance")) {
			return MimotoConfigManager.getproperty("mimoto-oidc-sunbird-partner-clientid");
		}

		return MimotoConfigManager.getproperty("mimoto-oidc-partner-clientid");
	}
	
	public static String inputstringKeyWordHandeler(String jsonString, String testCaseName) {
		if (jsonString.contains("$ID:")) {
			String autoGenIdFileName = mimotoAutoGeneratedIdPropFileName;
			jsonString = replaceIdWithAutogeneratedId(jsonString, "$ID:", autoGenIdFileName);
		}
		
		if (jsonString.contains(GlobalConstants.TIMESTAMP)) {
			jsonString = replaceKeywordValue(jsonString, GlobalConstants.TIMESTAMP, generateCurrentUTCTimeStamp());
		}
		
		if (jsonString.contains("$POLICYNUMBERFORSUNBIRDRC$")) {
			jsonString = replaceKeywordValue(jsonString, "$POLICYNUMBERFORSUNBIRDRC$",
					properties.getProperty("policyNumberForSunBirdRC"));
		}
		
		if (jsonString.contains("$FULLNAMEFORSUNBIRDRC$")) {
			jsonString = replaceKeywordValue(jsonString, "$FULLNAMEFORSUNBIRDRC$", fullNameForSunBirdRC);
		}
		
		if (jsonString.contains("$DOBFORSUNBIRDRC$")) {
			jsonString = replaceKeywordValue(jsonString, "$DOBFORSUNBIRDRC$", dobForSunBirdRC);
		}
		
		if (jsonString.contains("$CHALLENGEVALUEFORSUNBIRDC$")) {

			HashMap<String, String> mapForChallenge = new HashMap<String, String>();
			mapForChallenge.put(GlobalConstants.FULLNAME, fullNameForSunBirdRC);
			mapForChallenge.put(GlobalConstants.DOB, dobForSunBirdRC);

			String challenge = gson.toJson(mapForChallenge);

			String challengeValue = BiometricDataProvider.toBase64Url(challenge);

			jsonString = replaceKeywordValue(jsonString, "$CHALLENGEVALUEFORSUNBIRDC$", challengeValue);
		}
		
		if (jsonString.contains("$PUBLICKEYFORBINDING$")) {
			jsonString = replaceKeywordValue(jsonString, "$PUBLICKEYFORBINDING$",
					generatePublicKeyForMimoto());
		}
		
		if (jsonString.contains("$INJIREDIRECTURI$")) {
			jsonString = replaceKeywordValue(jsonString, "$INJIREDIRECTURI$",
					ApplnURI.replace(GlobalConstants.API_INTERNAL, "injiweb") + "/redirect");
		}
		
		
		return jsonString;
		
	}
	
	public static String replaceKeywordValue(String jsonString, String keyword, String value) {
		if (value != null && !value.isEmpty())
			return jsonString.replace(keyword, value);
		else {
			if (keyword.contains("$ID:"))
				throw new SkipException("Marking testcase as skipped as required field is empty " + keyword
						+ " please check the results of testcase: " + getTestCaseIDFromKeyword(keyword));
			else
				throw new SkipException("Marking testcase as skipped as required field is empty " + keyword);

		}
	}
	
	public static String generatePublicKeyForMimoto() {

		String vcString = "";
		try {
			KeyPairGenerator keyPairGenerator = getKeyPairGeneratorInstance();
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			PublicKey publicKey = keyPair.getPublic();
			StringWriter stringWriter = new StringWriter();
			try (JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
				pemWriter.writeObject(publicKey);
				pemWriter.flush();
				vcString = stringWriter.toString();
				if (System.getProperty("os.name").toLowerCase().contains("windows")) {
					vcString = vcString.replaceAll("\r\n", "\\\\n");
				} else {
					vcString = vcString.replaceAll("\n", "\\\\n");
				}
			} catch (Exception e) {
				throw e;
			}
		} catch (Exception e) {
			logger.error(e.getMessage());
		}
		return vcString;
	}
}