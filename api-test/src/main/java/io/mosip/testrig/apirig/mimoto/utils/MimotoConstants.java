package io.mosip.testrig.apirig.mimoto.utils;

public class MimotoConstants {
	
	public static final String SUNBIRD_INSURANCE_AUTH_FACTOR_TYPE = "KBI";
	
	public static final String SUNBIRD_INSURANCE_AUTH_FACTOR_TYPE_STRING = "sunbirdInsuranceAuthFactorType";
	
    public static final String ACTIVE_PROFILES = "activeProfiles";
	
	public static final String ESIGNET_ACTUATOR_ENDPOINT_KEYWORD = "actuatorEsignetEndpoint";
	
	public static final String ESIGNET_BASE_URL = MimotoConfigManager.getEsignetBaseUrl();
	
	public static final String ESIGNET_ACTUATOR_URL = ESIGNET_BASE_URL
			+ MimotoConfigManager.getproperty(ESIGNET_ACTUATOR_ENDPOINT_KEYWORD);
	
	public static final String SYSTEM_ENV_SECTION = "systemEnvironment";
	
    public static final String CLASS_PATH_APPLICATION_PROPERTIES = "classpath:/application.properties";
	
	public static final String MOSIP_ESIGNET_CAPTCHA_REQUIRED = "mosip.esignet.captcha.required";
	
	public static final String CLASS_PATH_APPLICATION_DEFAULT_PROPERTIES = "classpath:/application-default.properties";
	
	public static final String DEFAULT_STRING = "default";
	
	public static final String MOSIP_CONFIG_APPLICATION_HYPHEN_STRING = "mosip-config/application-";
	
	public static final String DOT_PROPERTIES_STRING = ".properties";

}