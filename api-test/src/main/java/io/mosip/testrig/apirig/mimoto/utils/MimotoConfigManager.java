package io.mosip.testrig.apirig.mimoto.utils;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;

import io.mosip.testrig.apirig.mimoto.testrunner.MosipTestRunner;
import io.mosip.testrig.apirig.utils.ConfigManager;

public class MimotoConfigManager extends ConfigManager{
	private static final Logger LOGGER = Logger.getLogger(MimotoConfigManager.class);
	
	public static void init() {
		Logger configManagerLogger = Logger.getLogger(ConfigManager.class);
		configManagerLogger.setLevel(Level.WARN);
		
		Map<String, Object> moduleSpecificPropertiesMap = new HashMap<>();
		// Load scope specific properties
		try {
			String path = MosipTestRunner.getGlobalResourcePath() + "/config/mimoto.properties";
			Properties props = getproperties(path);
			// Convert Properties to Map and add to moduleSpecificPropertiesMap
			for (String key : props.stringPropertyNames()) {
				String value = System.getenv(key) == null ? props.getProperty(key) : System.getenv(key);
				moduleSpecificPropertiesMap.put(key, value);
			}
		} catch (Exception e) {
			LOGGER.error(e.getMessage());
		}
		// Add module specific properties as well.
		init(moduleSpecificPropertiesMap);
	}
	
	public static String getSunbirdBaseURL() {
		return MimotoUtil.getValueFromMimotoActuator("overrides", "mosip.sunbird.url");
	}
	
	public static String getEsignetBaseUrl() {
		String esignetBaseUrl = null;
		if (getproperty("runPlugin").equals("mosipid")) {
			esignetBaseUrl = "https://" + MimotoUtil.getValueFromMimotoActuator("overrides", "mosip.esignet.mosipid.host");
		} else if (getproperty("runPlugin").equals("mockid")) {
			esignetBaseUrl = "https://" + MimotoUtil.getValueFromMimotoActuator("overrides", "mosip.esignet.mock.host");
		}

		return esignetBaseUrl;
	}
	
	public static String getEsignetSunBirdBaseURL() {
		return "https://" + MimotoUtil.getValueFromMimotoActuator("overrides", getproperty("mosip-esignet-insurance-host"));
	}

}
