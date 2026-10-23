package io.mosip.mimoto.controller;

import io.mosip.mimoto.exception.DeviceAttestationException;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.model.DevicePlatform;
import io.mosip.mimoto.service.device.DeviceNonceService;
import io.mosip.mimoto.service.device.DeviceRegistrationService;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

public class DeviceRegistrationControllerTest {

    private static final String BODY = """
            {"platform":"ANDROID","nonce":"n","public_key_jwk":{"kty":"EC","crv":"P-256","x":"x","y":"y"},"integrity_token":"t"}""";

    private DeviceNonceService nonceService;
    private DeviceRegistrationService registrationService;
    private MockMvc mockMvc;

    @Before
    public void setUp() {
        nonceService = mock(DeviceNonceService.class);
        registrationService = mock(DeviceRegistrationService.class);
        mockMvc = MockMvcBuilders.standaloneSetup(new DeviceRegistrationController(nonceService, registrationService)).build();
    }

    @Test
    public void should_returnNonceWithExpiryAndNoStore_when_nonceRequested() throws Exception {
        when(nonceService.issue()).thenReturn("abc");
        when(nonceService.ttlSeconds()).thenReturn(120L);

        mockMvc.perform(get("/device/nonce"))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.nonce").value("abc"))
                .andExpect(jsonPath("$.expires_in").value(120));
    }

    @Test
    public void should_return201WithNoBody_when_registered() throws Exception {
        mockMvc.perform(post("/device/register").contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isCreated())
                .andExpect(content().string(""));

        verify(registrationService).register(eq(DevicePlatform.ANDROID), eq("n"),
                argThat(jwk -> jwk.contains("\"crv\":\"P-256\"")), eq("t"));
    }

    @Test
    public void should_return400WithErrorCode_when_nonceInvalid() throws Exception {
        doThrow(new DeviceAttestationException(ErrorConstants.INVALID_NONCE, "detail not exposed"))
                .when(registrationService).register(any(), any(), any(), any());

        mockMvc.perform(post("/device/register").contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_nonce"))
                .andExpect(jsonPath("$.error_description").value(ErrorConstants.INVALID_NONCE.getErrorMessage()));
    }

    @Test
    public void should_return403_when_deviceRevoked() throws Exception {
        doThrow(new DeviceAttestationException(ErrorConstants.DEVICE_REVOKED, "revoked"))
                .when(registrationService).register(any(), any(), any(), any());

        mockMvc.perform(post("/device/register").contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("device_revoked"));
    }

    @Test
    public void should_return503_when_playIntegrityUnavailable() throws Exception {
        doThrow(new DeviceAttestationException(ErrorConstants.SERVER_UNAVAILABLE, "timeout"))
                .when(registrationService).register(any(), any(), any(), any());

        mockMvc.perform(post("/device/register").contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isServiceUnavailable());
    }

    @Test
    public void should_return400_when_publicKeyMissing() throws Exception {
        mockMvc.perform(post("/device/register").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"platform\":\"ANDROID\",\"nonce\":\"n\",\"integrity_token\":\"t\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
        verifyNoInteractions(registrationService);
    }
}
