package io.mosip.mimoto.controller;

import io.mosip.mimoto.config.device.DeviceAttestationProperties;
import io.mosip.mimoto.config.device.DeviceAttestationProperties.Mode;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.exception.DeviceAttestationException;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.security.device.DeviceProofFilter;
import io.mosip.mimoto.service.IdpService;
import io.mosip.mimoto.service.RestClientService;
import io.mosip.mimoto.service.device.DeviceProofVerifier;
import io.mosip.mimoto.util.JoseUtil;
import io.mosip.mimoto.util.RequestValidator;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.Map;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Runs the real IdpController behind the device proof filter to show both get-token endpoints are gated
 * and still receive the token form after the filter has read and hashed the body.
 */
public class IdpControllerDeviceProofTest {

    private static final String FORM = "grant_type=authorization_code&code=abc&client_id=wallet";

    private IdpService idpService;
    private DeviceProofVerifier verifier;

    @Before
    @SuppressWarnings("unchecked")
    public void setUp() throws Exception {
        idpService = mock(IdpService.class);
        verifier = mock(DeviceProofVerifier.class);
        when(idpService.getTokenResponseV2(anyMap(), any())).thenReturn(ResponseEntity.ok("{\"access_token\":\"at\"}"));
        TokenResponseDTO token = new TokenResponseDTO();
        token.setAccess_token("at");
        when(idpService.getTokenResponse(anyMap())).thenReturn(token);
    }

    @SuppressWarnings("unchecked")
    private MockMvc mvc(Mode mode) {
        DeviceAttestationProperties properties = new DeviceAttestationProperties();
        properties.setMode(mode);
        IdpController controller = new IdpController(mock(RestClientService.class), mock(JoseUtil.class), idpService, mock(RequestValidator.class));
        return MockMvcBuilders.standaloneSetup(controller)
                .addFilter(new DeviceProofFilter(verifier, properties, null), "/get-token/*", "/v2/get-token/*")
                .build();
    }

    @Test
    public void should_blockBothGetTokenEndpoints_when_enforceAndNoProof() throws Exception {
        when(verifier.verify(isNull(), anyString(), anyString(), any()))
                .thenThrow(new DeviceAttestationException(ErrorConstants.INVALID_DEVICE_PROOF, "device proof is missing"));
        MockMvc mvc = mvc(Mode.ENFORCE);

        for (String path : new String[]{"/v2/get-token/issuerX", "/get-token/issuerX"}) {
            mvc.perform(post(path).contentType(MediaType.APPLICATION_FORM_URLENCODED).content(FORM))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error").value("invalid_device_proof"));
        }
        verifyNoInteractions(idpService);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void should_forwardFormToIdpService_when_enforceAndProofValid() throws Exception {
        when(verifier.verify(eq("proof"), eq("POST"), eq("/v2/get-token/issuerX"), any())).thenReturn("thumbprint");

        mvc(Mode.ENFORCE).perform(post("/v2/get-token/issuerX").header(DeviceProofFilter.PROOF_HEADER, "proof")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED).content(FORM))
                .andExpect(status().isOk());

        verify(idpService).getTokenResponseV2(argThat((Map<String, String> p) ->
                "abc".equals(p.get("code")) && "wallet".equals(p.get("client_id")) && "issuerX".equals(p.get("issuer"))), isNull());
    }

    @Test
    public void should_allowGetToken_when_monitorAndNoProof() throws Exception {
        when(verifier.verify(any(), anyString(), anyString(), any()))
                .thenThrow(new DeviceAttestationException(ErrorConstants.INVALID_DEVICE_PROOF, "device proof is missing"));

        mvc(Mode.MONITOR).perform(post("/get-token/issuerX").contentType(MediaType.APPLICATION_FORM_URLENCODED).content(FORM))
                .andExpect(status().isOk());
        verify(idpService).getTokenResponse(anyMap());
    }
}
