package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerConfiguration;
import io.mosip.mimoto.exception.IssuerOnboardingException;
import io.mosip.mimoto.service.impl.IdpServiceImpl;
import io.mosip.mimoto.util.JoseUtil;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.util.MultiValueMap;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static io.mosip.mimoto.util.TestUtilities.*;

@RunWith(MockitoJUnitRunner.class)
public class IdpServiceTest {
    @InjectMocks
    private IdpServiceImpl idpService;

    @Mock
    JoseUtil joseUtil;

    private IssuerDTO issuerDTO;
    private Map<String, String> params;
    private final String authorizationAudience = "https://example.com/auth";

    @Before
    public void setUp() throws IOException {
        issuerDTO = new IssuerDTO();
        issuerDTO.setClient_id("client123");
        issuerDTO.setClient_alias("clientAlias");

        params = new HashMap<>();
        params.put("code", "sampleCode");
        params.put("grant_type", "authorization_code");
        params.put("redirect_uri", "https://myapp.com/callback");
        params.put("code_verifier", "verifier123");
    }

    @Test
    public void shouldConstructTokenRequestForTheValidIssuerAndParams() throws Exception {
        when(joseUtil.getJWT(eq("client123"), any(), any(), eq("clientAlias"), any(), eq(authorizationAudience)))
                .thenReturn("jwt-token");

        HttpEntity<MultiValueMap<String, String>> httpEntity =
                idpService.constructGetTokenRequest(params, issuerDTO, authorizationAudience);

        HttpHeaders headers = httpEntity.getHeaders();
        MultiValueMap<String, String> body = httpEntity.getBody();
        assertEquals(MediaType.APPLICATION_FORM_URLENCODED, headers.getContentType());
        assertNotNull(body);
        assertAll(
                () -> assertEquals("sampleCode", body.getFirst("code")),
                () -> assertEquals("client123", body.getFirst("client_id")),
                () -> assertEquals("authorization_code", body.getFirst("grant_type")),
                () -> assertEquals("https://myapp.com/callback", body.getFirst("redirect_uri")),
                () -> assertEquals("jwt-token", body.getFirst("client_assertion")),
                () -> assertEquals("verifier123", body.getFirst("code_verifier"))
        );
    }

    @Test
    public void shouldThrowExceptionIfThereIsAnyErrorOccurredWhileFetchingP12File() throws IOException {
        String expectedExceptionMsg = "RESIDENT-APP-037 --> Private Key Entry is Missing for the alias clientAlias";
        when(joseUtil.getJWT(eq("client123"), any(), any(), eq("clientAlias"), any(), eq(authorizationAudience)))
                .thenThrow(new IssuerOnboardingException("Private Key Entry is Missing for the alias clientAlias"));

        IssuerOnboardingException actualException = assertThrows(IssuerOnboardingException.class, () ->
                idpService.constructGetTokenRequest(params, issuerDTO, authorizationAudience));

        assertEquals(expectedExceptionMsg, actualException.getMessage());
    }

    @Test
    public void shouldReturnTokenEndpointFromCredentialIssuerConfigurationResponse() {
        CredentialIssuerConfiguration credentialIssuerConfiguration =
                getCredentialIssuerConfigurationResponseDto("Issuer1", "CredentialType1", List.of());
        String expectedTokenEndpoint = "https://dev/token";

        String actualTokenEndpoint = idpService.getTokenEndpoint(credentialIssuerConfiguration);

        assertEquals(expectedTokenEndpoint, actualTokenEndpoint);
    }
}