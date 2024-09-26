package io.mosip.mimoto.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

@Configuration
public class InjiConfiguration {
    @Bean
    @ConfigurationProperties(prefix = "mosip.inji")
    public Map<String, String> injiConfig() {
        return new HashMap<>();
    }

}
