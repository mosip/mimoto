package io.inji.testrig.apirig.mimoto.testscripts;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.json.JSONObject;
import org.testng.ITest;
import org.testng.ITestContext;
import org.testng.ITestResult;
import org.testng.Reporter;
import org.testng.SkipException;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.parser.PdfTextExtractor;

import io.inji.testrig.apirig.mimoto.utils.MimotoConfigManager;
import io.inji.testrig.apirig.mimoto.utils.MimotoUtil;
import io.mosip.testrig.apirig.dto.TestCaseDTO;
import io.mosip.testrig.apirig.testrunner.BaseTestCase;
import io.mosip.testrig.apirig.testrunner.HealthChecker;
import io.mosip.testrig.apirig.utils.AdminTestException;
import io.mosip.testrig.apirig.utils.AdminTestUtil;
import io.mosip.testrig.apirig.utils.AuthenticationTestException;
import io.mosip.testrig.apirig.utils.GlobalConstants;
import io.mosip.testrig.apirig.utils.GlobalMethods;
import io.mosip.testrig.apirig.utils.SecurityXSSException;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;

public class PostWithFormDataBodyForPdfDownload extends MimotoUtil implements ITest {
	private static final Logger logger = Logger.getLogger(PostWithFormDataBodyForPdfDownload.class);
	protected String testCaseName = "";
	public Response response = null;
	public byte[] pdf=null;
	public String pdfAsText =null;
	
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
		logger.info("Started executing yml: "+ymlFile);
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
		testCaseDTO = MimotoUtil.changeContextURLByFlag(testCaseDTO);
		if (HealthChecker.signalTerminateExecution) {
			throw new SkipException(GlobalConstants.TARGET_ENV_HEALTH_CHECK_FAILED + HealthChecker.healthCheckFailureMapS);
		}
		
		if (testCaseDTO.getTestCaseName().contains("VID") || testCaseDTO.getTestCaseName().contains("Vid")) {
			if (!BaseTestCase.getSupportedIdTypesValueFromActuator().contains("VID")
					&& !BaseTestCase.getSupportedIdTypesValueFromActuator().contains("vid")) {
				throw new SkipException(GlobalConstants.VID_FEATURE_NOT_SUPPORTED);
			}
		}
		
		String inputJson = getJsonFromTemplate(testCaseDTO.getInput(), testCaseDTO.getInputTemplate());
		inputJson = MimotoUtil.inputstringKeyWordHandeler(inputJson, testCaseName);

		pdf = postWithFormDataBodyForPdfWithStateHeaderAndCookie(ApplnURI + testCaseDTO.getEndPoint(), inputJson);
		PdfReader pdfReader = null;
		ByteArrayInputStream bIS = null;
		
		try {
			bIS = new ByteArrayInputStream(pdf);
			pdfReader = new PdfReader(bIS);
			pdfAsText = PdfTextExtractor.getTextFromPage(pdfReader, 1);
		} catch (IOException e) {
			Reporter.log("Exception : " + e.getMessage());
		} finally {
			AdminTestUtil.closeByteArrayInputStream(bIS);
			AdminTestUtil.closePdfReader(pdfReader);
		}
		 
		if (pdf != null && (new String(pdf).contains("errors") || pdfAsText == null)) {
			// pdf bytes are actually a JSON error body here, not a PDF - surface it instead of "null"
			GlobalMethods.reportResponse(null, ApplnURI + testCaseDTO.getEndPoint(),
					"Not able to download issuer credential. Raw response: " + new String(pdf));
			if (!testCaseName.contains("_Neg")) {
				throw new AdminTestException("Not able to download issuer credential");
			}
		} else {
			GlobalMethods.reportResponse(null, ApplnURI + testCaseDTO.getEndPoint(), pdfAsText);
		}
		
	}

	/**
	 * Posts the credential download request as form data, additionally forwarding a
	 * DPoP "state" header and a guest DPoP session cookie when present in the input
	 * JSON (both are removed from the form body since the backend expects them as
	 * a header/cookie, not form fields).
	 */
	private byte[] postWithFormDataBodyForPdfWithStateHeaderAndCookie(String url, String inputJson) {
		JSONObject json = new JSONObject(inputJson);
		String state = json.optString("state", "");
		String cookieValue = json.optString("cookie", "");
		String cookieName = json.optString("cookieName", "");
		json.remove("state");
		json.remove("cookie");
		json.remove("cookieName");

		Map<String, String> formParams = new HashMap<>();
		Iterator<String> keys = json.keys();
		while (keys.hasNext()) {
			String key = keys.next();
			formParams.put(key, String.valueOf(json.get(key)));
		}

		RequestSpecification request = RestAssured.given().relaxedHTTPSValidation().contentType(ContentType.URLENC)
				.formParams(formParams)
				.header("X-XSRF-TOKEN", BaseTestCase.CSRF_TOKEN)
				.cookie("XSRF-TOKEN", BaseTestCase.CSRF_COOKIE);
		if (!state.isBlank()) {
			request = request.header("state", state);
		}
		if (!cookieValue.isBlank() && !cookieName.isBlank()) {
			request = request.cookie(cookieName, cookieValue);
		}
		Response response = request.post(url);
		return response.asByteArray();
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
}
