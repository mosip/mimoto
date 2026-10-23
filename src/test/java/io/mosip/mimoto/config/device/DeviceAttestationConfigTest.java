package io.mosip.mimoto.config.device;

import io.mosip.mimoto.security.device.DeviceProofFilter;
import io.mosip.mimoto.service.device.DeviceProofVerifier;
import org.junit.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

public class DeviceAttestationConfigTest {

    @Test
    @SuppressWarnings("unchecked")
    public void should_runDeviceProofFilterBeforeSpringSecurity_when_registered() {
        FilterRegistrationBean<DeviceProofFilter> registration = new DeviceAttestationConfig().deviceProofFilter(
                mock(DeviceProofVerifier.class), new DeviceAttestationProperties(), mock(ObjectProvider.class));

        // Spring Security reads form parameters, which consumes the body the proof's req_hash covers
        assertTrue(registration.getOrder() < SecurityProperties.DEFAULT_FILTER_ORDER,
                "order " + registration.getOrder() + " must be before " + SecurityProperties.DEFAULT_FILTER_ORDER);
        assertTrue(registration.getUrlPatterns().containsAll(List.of("/get-token/*", "/v2/get-token/*")));
    }
}
