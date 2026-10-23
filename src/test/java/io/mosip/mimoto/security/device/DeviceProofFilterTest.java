package io.mosip.mimoto.security.device;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.mosip.mimoto.config.device.DeviceAttestationProperties;
import io.mosip.mimoto.config.device.DeviceAttestationProperties.Mode;
import io.mosip.mimoto.exception.DeviceAttestationException;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.service.device.DeviceProofVerifier;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

public class DeviceProofFilterTest {

    private static final String FORM = "grant_type=authorization_code&code=abc%2B1&redirect_uri=io.mosip.residentapp.inji%3A%2F%2Foauthredirect";

    @RestController
    static class EchoTokenController {
        @PostMapping(value = "/v2/get-token/{issuer}", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
        public Map<String, String> token(@RequestParam Map<String, String> params, @PathVariable("issuer") String issuer) {
            return Map.of("issuer", issuer, "code", params.get("code"), "redirect_uri", params.get("redirect_uri"));
        }
    }

    private DeviceProofVerifier verifier;
    private SimpleMeterRegistry meters;

    @Before
    public void setUp() {
        verifier = mock(DeviceProofVerifier.class);
        meters = new SimpleMeterRegistry();
    }

    private MockMvc mvc(Mode mode) {
        DeviceAttestationProperties properties = new DeviceAttestationProperties();
        properties.setMode(mode);
        return MockMvcBuilders.standaloneSetup(new EchoTokenController())
                .addFilters(new DeviceProofFilter(verifier, properties, meters))
                .build();
    }

    private void proofRejected() {
        when(verifier.verify(any(), anyString(), anyString(), any()))
                .thenThrow(new DeviceAttestationException(ErrorConstants.DEVICE_NOT_REGISTERED, "unknown kid"));
    }

    private double count(String mode, String outcome) {
        var counter = meters.find("mimoto.device.proof").tags("mode", mode, "outcome", outcome).counter();
        return counter == null ? 0 : counter.count();
    }

    @Test
    public void should_passThroughWithoutChecking_when_modeOff() throws Exception {
        mvc(Mode.OFF).perform(post("/v2/get-token/issuerX").contentType(MediaType.APPLICATION_FORM_URLENCODED).content(FORM))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value("abc+1"));
        verifyNoInteractions(verifier);
    }

    @Test
    public void should_passAndRecord_when_monitorAndProofInvalid() throws Exception {
        proofRejected();

        mvc(Mode.MONITOR).perform(post("/v2/get-token/issuerX").contentType(MediaType.APPLICATION_FORM_URLENCODED).content(FORM))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value("abc+1"));
        assertEquals(1, count("monitor", "device_not_registered"));
    }

    @Test
    public void should_return401WithErrorCode_when_enforceAndProofInvalid() throws Exception {
        proofRejected();

        mvc(Mode.ENFORCE).perform(post("/v2/get-token/issuerX").contentType(MediaType.APPLICATION_FORM_URLENCODED).content(FORM))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("device_not_registered"))
                .andExpect(jsonPath("$.error_description").value(ErrorConstants.DEVICE_NOT_REGISTERED.getErrorMessage()));
        assertEquals(1, count("enforce", "device_not_registered"));
    }

    @Test
    public void should_hashExactBodyAndStillBindForm_when_enforceAndProofValid() throws Exception {
        when(verifier.verify(eq("the-proof"), eq("POST"), eq("/v2/get-token/issuerX"), eq(FORM.getBytes(StandardCharsets.UTF_8))))
                .thenReturn("thumbprint");

        mvc(Mode.ENFORCE).perform(post("/v2/get-token/issuerX").header(DeviceProofFilter.PROOF_HEADER, "the-proof")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED).content(FORM))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value("issuerX"))
                .andExpect(jsonPath("$.code").value("abc+1"))
                .andExpect(jsonPath("$.redirect_uri").value("io.mosip.residentapp.inji://oauthredirect"));
        assertEquals(1, count("enforce", "valid"));
    }

    @Test
    public void should_return503_when_enforceAndCheckFailsUnexpectedly() throws Exception {
        when(verifier.verify(any(), anyString(), anyString(), any())).thenThrow(new RuntimeException("db down"));

        mvc(Mode.ENFORCE).perform(post("/v2/get-token/issuerX").contentType(MediaType.APPLICATION_FORM_URLENCODED).content(FORM))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.error").value("server_unavailable"));
    }

    @Test
    public void should_rejectOversizedBody_when_enforce() throws Exception {
        mvc(Mode.ENFORCE).perform(post("/v2/get-token/issuerX").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content("code=" + "a".repeat(70 * 1024)))
                .andExpect(status().isPayloadTooLarge());
        verifyNoInteractions(verifier);
    }
}
