package io.mosip.mimoto.service.device;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.config.device.DeviceAttestationProperties;
import io.mosip.mimoto.repository.DeviceRegistrationRepository;
import org.junit.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.web.client.RestTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Starts the device attestation services the way Spring creates them, so a constructor Spring
 * cannot choose fails here rather than at application startup.
 */
public class DeviceAttestationContextTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withBean(DeviceAttestationProperties.class)
            .withBean(ObjectMapper.class)
            .withBean("playIntegrityRestTemplate", RestTemplate.class)
            .withBean(DeviceRegistrationRepository.class, () -> mock(DeviceRegistrationRepository.class))
            .withBean(InMemoryDeviceNonceStore.class)
            .withBean(DeviceNonceService.class)
            .withBean(GoogleServiceAccountTokenProvider.class)
            .withBean(PlayIntegrityVerifier.class)
            .withBean(DeviceRegistrationService.class)
            .withBean(DeviceProofVerifier.class);

    @Test
    public void should_createDeviceAttestationServices_when_wiredBySpring() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(GoogleServiceAccountTokenProvider.class);
            assertThat(context).hasSingleBean(PlayIntegrityVerifier.class);
            assertThat(context).hasSingleBean(DeviceRegistrationService.class);
            assertThat(context).hasSingleBean(DeviceProofVerifier.class);
        });
    }
}
