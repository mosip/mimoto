package io.inji.testrig.apirig.mimoto.utils;

public class MimotoConstants {
	
	public static final String SUNBIRD_INSURANCE_AUTH_FACTOR_TYPE = "KBI";
	
	public static final String SUNBIRD_INSURANCE_AUTH_FACTOR_TYPE_STRING = "sunbirdInsuranceAuthFactorType";

	// api-internal gateway enforces a double-submit XSRF cookie/header pair; any matching value passes it
	public static final String XSRF_BYPASS_VALUE = "apitest-xsrf-bypass";
	public static final String XSRF_HEADER_NAME = "X-XSRF-TOKEN";
	public static final String XSRF_COOKIE_NAME = "XSRF-TOKEN";

}