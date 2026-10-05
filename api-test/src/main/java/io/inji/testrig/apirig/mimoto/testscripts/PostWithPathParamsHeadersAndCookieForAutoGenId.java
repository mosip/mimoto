package io.inji.testrig.apirig.mimoto.testscripts;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.testng.ITest;
import org.testng.ITestContext;
import org.testng.ITestResult;
import org.testng.Reporter;
import org.testng.SkipException;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import io.inji.testrig.apirig.mimoto.utils.MimotoConfigManager;
import io.inji.testrig.apirig.mimoto.utils.MimotoUtil;
import io.mosip.testrig.apirig.dto.OutputValidationDto;
import io.mosip.testrig.apirig.dto.TestCaseDTO;
import io.mosip.testrig.apirig.testrunner.HealthChecker;
import io.mosip.testrig.apirig.utils.AdminTestException;
import io.mosip.testrig.apirig.utils.AuthenticationTestException;
import io.mosip.testrig.apirig.utils.GlobalConstants;
import io.mosip.testrig.apirig.utils.GlobalMethods;
import io.mosip.testrig.apirig.utils.OutputValidationUtil;
import io.mosip.testrig.apirig.utils.ReportUtil;
import io.mosip.testrig.apirig.utils.SecurityXSSException;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import org.json.JSONObject;

public class PostWithPathParamsHeadersAndCookieForAutoGenId extends MimotoUtil implements ITest {
	private static final Logger logger = Logger.getLogger(PostWithPathParamsHeadersAndCookieForAutoGenId.class);
	// api-internal gateway enforces a double-submit XSRF cookie/header pair; any matching value passes it
	private static final String XSRF_BYPASS_VALUE = "apitest-xsrf-bypass";
	private static final String XSRF_HEADER_NAME = "X-XSRF-TOKEN";
	private static final String XSRF_COOKIE_NAME = "XSRF-TOKEN";
	protected String testCaseName = "";
	public String pathParams = null;
	public String headers = null;
	public String idKeyName = null;

	@BeforeClass
	public static void setLogLevel() {
		if (MimotoConfigManager.IsDebugEnabled())
			logger.setLevel(Level.ALL);
		else
			logger.setLevel(Level.ERROR);
	}

	/**
	 * get current testcaseName
	 */
	@Override
	public String getTestName() {
		return testCaseName;
	}

	/**
	 * Data provider class provides test case list
	 * 
	 * @return object of data provider
	 */
	@DataProvider(name = "testcaselist")
	public Object[] getTestCaseList(ITestContext context) {
		String ymlFile = context.getCurrentXmlTest().getLocalParameters().get("ymlFile");
		pathParams = context.getCurrentXmlTest().getLocalParameters().get("pathParams");
		idKeyName = context.getCurrentXmlTest().getLocalParameters().get("idKeyName");
		headers = context.getCurrentXmlTest().getLocalParameters().get("headers");
		logger.info("Started executing yml: " + ymlFile);
		return getYmlTestData(ymlFile);
	}

	/**
	 * Test method for OTP Generation execution
	 * 
	 * @param objTestParameters
	 * @param testScenario
	 * @param testcaseName
	 * @throws AuthenticationTestException
	 * @throws AdminTestException
	 */
	@Test(dataProvider = "testcaselist")
	public void test(TestCaseDTO testCaseDTO) throws AuthenticationTestException, AdminTestException, SecurityXSSException {
		testCaseName = testCaseDTO.getTestCaseName();
		testCaseDTO = MimotoUtil.isTestCaseValidForTheExecution(testCaseDTO);
		
		if (HealthChecker.signalTerminateExecution) {
			throw new SkipException(
					GlobalConstants.TARGET_ENV_HEALTH_CHECK_FAILED + HealthChecker.healthCheckFailureMapS);
		}

	
		String inputJson = getJsonFromTemplate(testCaseDTO.getInput(), testCaseDTO.getInputTemplate());
		inputJson = MimotoUtil.inputstringKeyWordHandeler(inputJson, testCaseName);

		// Inject the double-submit XSRF cookie/header pair so the api-internal gateway CSRF check
		// passes without leaking those fields into the yml/hbs. Only applied for the guest DPoP
		// flow (role=userDefinedCookie) to avoid polluting request bodies of other tests that use
		// this script class with a real MOSIP auth role.
		if ("userDefinedCookie".equals(testCaseDTO.getRole())) {
			inputJson = injectXsrfBypass(inputJson);
		}

		if (inputJson.contains("authorizationRequestUrl")) {

			try {

				JSONObject json = new JSONObject(inputJson);
				if (json.has("authorizationRequestUrl")) {
					String authUrl = json.getString("authorizationRequestUrl");

					authUrl = authUrl.replace("&amp;", "&").replace("%25", "%").replace("\\u0026", "&")
							.replace("\\u003d", "=");
					json.put("authorizationRequestUrl", authUrl);
					inputJson = json.toString();
				}
			} catch (Exception e) {
				logger.warn("Warning: Unable to normalize authorizationRequestUrl");
			}
		}

		Response response;
		// The closed-source commons method attaches only ONE cookie via the userDefinedCookie role.
		// For flows that must forward a real session cookie (e.g. Google login SESSION) AND the
		// XSRF-TOKEN cookie for the gateway's double-submit CSRF check, route to a manual
		// RestAssured call that sends both cookies.
		if (needsDualCookiePath(testCaseDTO.getRole(), inputJson)) {
			response = manualPostWithSessionAndXsrf(testCaseDTO.getEndPoint(), inputJson,
					testCaseDTO.getTestCaseName());
		} else {
			response = postWithPathParamsBodyHeadersAndCookieForAutoGeneratedId(
					ApplnURI + testCaseDTO.getEndPoint(), inputJson, COOKIENAME, testCaseDTO.getRole(),
					testCaseDTO.getTestCaseName(), pathParams, idKeyName, headers);
		}

		// Unlike SimplePostForAutoGenId, the closed-source commons call site here never scans
		// Set-Cookie for a SESSION= value, so `sessionCookie` idKeyName must be captured manually
		// via the same public writeAutoGeneratedId(...) the framework uses.
		if (idKeyName != null && idKeyName.contains("sessionCookie")) {
			captureSessionCookie(response, testCaseDTO.getTestCaseName());
		}

		Map<String, List<OutputValidationDto>> ouputValid = OutputValidationUtil.doJsonOutputValidation(
				response.asString(), getJsonFromTemplate(testCaseDTO.getOutput(), testCaseDTO.getOutputTemplate()),
				testCaseDTO, response.getStatusCode());
		Reporter.log(ReportUtil.getOutputValidationReport(ouputValid));

		if (!OutputValidationUtil.publishOutputResult(ouputValid))
			throw new AdminTestException("Failed at output validation");

	}

	/**
	 * The method ser current test name to result
	 * 
	 * @param result
	 */
	@AfterMethod(alwaysRun = true)
	public void setResultTestName(ITestResult result) {
		result.setAttribute("TestCaseName", testCaseName);
	}

	/**
	 * Injects the XSRF header field (extracted by the closed-source `headers` loop) and the
	 * userDefinedCookie fields (used by the closed-source role handling to set the XSRF cookie)
	 * into the request JSON. Keeps the yml/hbs clean of gateway-CSRF plumbing.
	 */
	private String injectXsrfBypass(String inputJson) {
		try {
			JSONObject json = new JSONObject(inputJson);
			String xsrfValue = fetchRealXsrfToken(null, null);
			if (xsrfValue == null || xsrfValue.isBlank()) {
				xsrfValue = XSRF_BYPASS_VALUE;
			}
			if (!json.has(XSRF_HEADER_NAME)) {
				json.put(XSRF_HEADER_NAME, xsrfValue);
			}
			if (!json.has("cookie")) {
				json.put("cookie", xsrfValue);
			}
			if (!json.has("cookieName")) {
				json.put("cookieName", XSRF_COOKIE_NAME);
			}
			return json.toString();
		} catch (Exception e) {
			logger.warn("Warning: Unable to inject XSRF bypass fields into input JSON");
			return inputJson;
		}
	}

	/**
	 * Dual-cookie path is needed when the yml is forwarding a real session cookie (not the
	 * XSRF-TOKEN bypass) — the request must carry both that session cookie AND the XSRF-TOKEN
	 * cookie/header to pass the gateway CSRF check.
	 */
	private boolean needsDualCookiePath(String role, String inputJson) {
		if (!"userDefinedCookie".equals(role)) {
			return false;
		}
		try {
			JSONObject json = new JSONObject(inputJson);
			return json.has("cookie") && json.has("cookieName")
					&& !XSRF_COOKIE_NAME.equals(json.optString("cookieName"));
		} catch (Exception e) {
			return false;
		}
	}

	/**
	 * Primes a real Spring Security CSRF cookie via a lightweight public GET — Config.java's
	 * CsrfTokenCookieFilter issues a fresh XSRF-TOKEN cookie on every GET, even unauthenticated
	 * ones. Attaches the caller's session cookie when provided (Google login flow) so the
	 * priming call runs in the same session context as the real request. Returns null on any
	 * failure so callers can fall back to the dummy double-submit value.
	 */
	private String fetchRealXsrfToken(String sessionCookieName, String sessionCookieValue) {
		try {
			RequestSpecification request = RestAssured.given().relaxedHTTPSValidation();
			if (sessionCookieName != null && sessionCookieValue != null
					&& !sessionCookieName.isBlank() && !sessionCookieValue.isBlank()) {
				request = request.cookie(sessionCookieName, sessionCookieValue);
			}
			Response response = request.get(ApplnURI + "/v1/mimoto/issuers");
			return response.getCookie(XSRF_COOKIE_NAME);
		} catch (Exception e) {
			logger.warn("Warning: Unable to fetch a real XSRF-TOKEN, falling back to a dummy value");
			return null;
		}
	}

	/**
	 * Builds and sends the POST directly via RestAssured, attaching both the caller-supplied
	 * session cookie (Google login SESSION) and a real XSRF-TOKEN cookie/header. Also captures
	 * idKeyName body-field values via the same public writeAutoGeneratedId(...) the framework
	 * uses.
	 */
	private Response manualPostWithSessionAndXsrf(String endPoint, String inputJson,
			String currentTestCaseName) {
		JSONObject json = new JSONObject(inputJson);
		String cookieValue = json.optString("cookie", "");
		String cookieName = json.optString("cookieName", "");
		json.remove("cookie");
		json.remove("cookieName");
		json.remove(XSRF_HEADER_NAME);

		Map<String, String> pathParamsMap = new HashMap<>();
		if (pathParams != null) {
			for (String p : pathParams.split(",")) {
				String key = p.trim();
				if (!key.isEmpty() && json.has(key)) {
					pathParamsMap.put(key, String.valueOf(json.get(key)));
					json.remove(key);
				}
			}
		}

		Map<String, String> headersMap = new HashMap<>();
		if (headers != null) {
			for (String h : headers.split(",")) {
				String key = h.trim();
				if (key.isEmpty() || XSRF_HEADER_NAME.equals(key)) {
					continue;
				}
				if (json.has(key)) {
					headersMap.put(key, String.valueOf(json.get(key)));
					json.remove(key);
				}
			}
		}
		// Prime a real server-issued XSRF-TOKEN using the same session cookie, falling back to
		// the dummy double-submit value if the priming call fails.
		String xsrfValue = fetchRealXsrfToken(cookieName, cookieValue);
		if (xsrfValue == null || xsrfValue.isBlank()) {
			xsrfValue = XSRF_BYPASS_VALUE;
		}
		headersMap.put(XSRF_HEADER_NAME, xsrfValue);

		String bodyStr = json.toString();
		String url = ApplnURI + endPoint;
		GlobalMethods.reportRequest(headersMap.toString(), bodyStr, url);

		RequestSpecification request = RestAssured.given().relaxedHTTPSValidation()
				.contentType(ContentType.JSON)
				.accept(ContentType.JSON)
				.headers(headersMap)
				.cookie(XSRF_COOKIE_NAME, xsrfValue)
				.body(bodyStr);
		if (!pathParamsMap.isEmpty()) {
			request = request.pathParams(pathParamsMap);
		}
		if (!cookieValue.isBlank() && !cookieName.isBlank()) {
			request = request.cookie(cookieName, cookieValue);
		}
		Response response = request.post(url);
		GlobalMethods.reportResponse(response.getHeaders().asList().toString(), url, response);

		// Mirror the closed-source auto-gen capture: only write when the test case name has _sid
		if (idKeyName != null && currentTestCaseName != null
				&& currentTestCaseName.toLowerCase().contains("_sid")) {
			try {
				JSONObject respBody = new JSONObject(response.asString());
				for (String key : idKeyName.split(",")) {
					String field = key.trim();
					if ("sessionCookie".equals(field) || field.isEmpty()) {
						continue;
					}
					if (respBody.has(field)) {
						// writeAutoGeneratedId's param order is (testCaseName, fieldName, value)
						writeAutoGeneratedId(currentTestCaseName, field, String.valueOf(respBody.get(field)));
					} else if ("id".equals(field) && respBody.has("verifier")
							&& respBody.getJSONObject("verifier").has("id")) {
						// VerifiablePresentationAuthorization nests "id" under "verifier", not top-level
						writeAutoGeneratedId(currentTestCaseName, field,
								respBody.getJSONObject("verifier").getString("id"));
					}
				}
			} catch (Exception e) {
				logger.warn("Warning: Unable to capture idKeyName from response body: " + e.getMessage());
			}
		}
		return response;
	}

	/**
	 * Manually replicates the closed-source SESSION= cookie capture that
	 * postRequestWithCookieAuthHeaderAndXsrfTokenForAutoGenId performs internally (used by
	 * GoogleLoginToken) — this script's own commons call site never scans Set-Cookie headers,
	 * so downstream `$ID:<sid>_sessionCookie$` references would otherwise resolve empty.
	 * Stores only the value after "SESSION=" to match the closed-source cache format exactly.
	 */
	private void captureSessionCookie(Response response, String currentTestCaseName) {
		for (String setCookieHeader : response.getHeaders().getValues("Set-Cookie")) {
			for (String cookiePart : setCookieHeader.split(";")) {
				String trimmed = cookiePart.trim();
				if (trimmed.startsWith("SESSION=")) {
					// writeAutoGeneratedId's param order is (testCaseName, fieldName, value)
					writeAutoGeneratedId(currentTestCaseName, "sessionCookie", trimmed.split("=")[1]);
					return;
				}
			}
		}
		logger.warn("Warning: No SESSION cookie found in response to capture as sessionCookie");
	}

}