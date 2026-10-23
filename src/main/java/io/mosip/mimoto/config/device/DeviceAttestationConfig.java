package io.mosip.mimoto.config.device;

import io.micrometer.core.instrument.MeterRegistry;
import io.mosip.mimoto.security.device.DeviceProofFilter;
import io.mosip.mimoto.service.device.DeviceProofVerifier;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;

@Configuration
public class DeviceAttestationConfig {

    /**
     * Client for Google's OAuth token endpoint and the Play Integrity API, with explicit timeouts
     * so a slow Google call cannot hold a registration request indefinitely.
     */
    @Bean("playIntegrityRestTemplate")
    public RestTemplate playIntegrityRestTemplate(RestTemplateBuilder builder) {
        return builder
                .setConnectTimeout(Duration.ofSeconds(5))
                .setReadTimeout(Duration.ofSeconds(10))
                .build();
    }

    /**
     * Applies the device proof check to the get-token endpoints only. Paths are relative to the servlet context.
     * Runs first: Spring Security and other filters read form parameters, which consumes the request body that
     * the proof's req_hash covers.
     */
    @Bean
    public FilterRegistrationBean<DeviceProofFilter> deviceProofFilter(DeviceProofVerifier verifier,
                                                                       DeviceAttestationProperties properties,
                                                                       ObjectProvider<MeterRegistry> meterRegistry) {
        FilterRegistrationBean<DeviceProofFilter> registration =
                new FilterRegistrationBean<>(new DeviceProofFilter(verifier, properties, meterRegistry.getIfAvailable()));
        registration.addUrlPatterns("/get-token/*", "/v2/get-token/*");
        registration.setName("deviceProofFilter");
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return registration;
    }
}
