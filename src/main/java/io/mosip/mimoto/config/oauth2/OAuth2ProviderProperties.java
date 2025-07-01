package io.mosip.mimoto.config.oauth2;

import io.mosip.mimoto.dto.ProviderDataConfig;
import jakarta.annotation.PostConstruct;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.Map;

@Configuration
@ConfigurationProperties(prefix = "spring.security.oauth2.client")
@Slf4j
@Data
public class OAuth2ProviderProperties {
    private Map<String, ProviderDataConfig> provider;

    @PostConstruct
    public void logProviders() {
        if (provider == null || provider.isEmpty()) {
            log.warn("No OAuth2 providers configured under 'spring.security.oauth2.client.provider'");
        } else {
            log.info("Loaded OAuth2 providers: {}", provider.keySet());
            provider.forEach((key, prov) -> log.debug("Provider {}: {}", key, prov));
        }
    }

}