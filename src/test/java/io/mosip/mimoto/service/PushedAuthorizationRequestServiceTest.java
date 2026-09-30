package io.mosip.mimoto.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.mimoto.PushedAuthorizationResponse;
import io.mosip.mimoto.exception.PushedAuthorizationRequestException;
import io.mosip.mimoto.util.JoseUtil;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class PushedAuthorizationRequestServiceTest {

    private static final String PAR_ENDPOINT = "https://dev/par";
    private static final String CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    @Mock
    private JoseUtil joseUtil;

    @Mock
    private RestTemplate restTemplate;

    private PushedAuthorizationRequestService service;

    @Before
    public void setUp() throws Exception {
        service = new PushedAuthorizationRequestService(
                joseUtil, restTemplate, new ObjectMapper(),
                CLIENT_ASSERTION_TYPE, "keystore.p12", "password", "/keys/");
        when(joseUtil.getJWT(eq("client-1"), eq("/keys/"), eq("keystore.p12"), eq("alias-1"), eq("password"), eq(PAR_ENDPOINT)))
                .thenReturn("header.payload.sig");
    }

    @Test
    public void shouldPostAuthorizationParametersAndReturnRequestUri() throws Exception {
        when(restTemplate.postForObject(eq(PAR_ENDPOINT), any(HttpEntity.class), eq(String.class)))
                .thenReturn("{\"request_uri\":\"urn:example:request\",\"expires_in\":60}");

        PushedAuthorizationResponse actual = service.pushAuthorizationRequest(
                PAR_ENDPOINT, issuer(), "https://wallet.example/redirect", "openid credential",
                "state-1", "challenge", "S256", "en", "thumbprint");

        assertEquals("urn:example:request", actual.getRequestUri());
        assertEquals(Long.valueOf(60L), actual.getExpiresIn());

        @SuppressWarnings("unchecked")
        ArgumentCaptor<HttpEntity<MultiValueMap<String, String>>> captor = ArgumentCaptor.forClass(HttpEntity.class);
        verify(restTemplate).postForObject(eq(PAR_ENDPOINT), captor.capture(), eq(String.class));
        MultiValueMap<String, String> body = captor.getValue().getBody();
        assertEquals("code", body.getFirst("response_type"));
        assertEquals("client-1", body.getFirst("client_id"));
        assertEquals("https://wallet.example/redirect", body.getFirst("redirect_uri"));
        assertEquals("openid credential", body.getFirst("scope"));
        assertEquals("state-1", body.getFirst("state"));
        assertEquals("challenge", body.getFirst("code_challenge"));
        assertEquals("S256", body.getFirst("code_challenge_method"));
        assertEquals("en", body.getFirst("ui_locales"));
        assertEquals("thumbprint", body.getFirst("dpop_jkt"));
        assertEquals("header.payload.sig", body.getFirst("client_assertion"));
        assertEquals(CLIENT_ASSERTION_TYPE, body.getFirst("client_assertion_type"));
        verify(joseUtil).getJWT("client-1", "/keys/", "keystore.p12", "alias-1", "password", PAR_ENDPOINT);
    }

    @Test
    public void shouldFailWhenResponseOmitsRequestUri() {
        when(restTemplate.postForObject(eq(PAR_ENDPOINT), any(HttpEntity.class), eq(String.class)))
                .thenReturn("{\"expires_in\":60}");

        PushedAuthorizationRequestException exception = assertThrows(PushedAuthorizationRequestException.class,
                () -> service.pushAuthorizationRequest(PAR_ENDPOINT, issuer(), "https://wallet.example/redirect", "scope",
                        "state-1", "challenge", "S256", null, null));

        assertTrue(exception.getMessage().contains("did not contain a request_uri"));
    }

    @Test
    public void shouldFailWhenAuthorizationServerRejectsTheClient() {
        when(restTemplate.postForObject(eq(PAR_ENDPOINT), any(HttpEntity.class), eq(String.class)))
                .thenThrow(new HttpClientErrorException(HttpStatus.UNAUTHORIZED, "Unauthorized",
                        "{\"error\":\"invalid_client\"}".getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8));

        PushedAuthorizationRequestException exception = assertThrows(PushedAuthorizationRequestException.class,
                () -> service.pushAuthorizationRequest(PAR_ENDPOINT, issuer(), "https://wallet.example/redirect", "scope",
                        "state-1", "challenge", "S256", "en", "thumbprint"));

        assertTrue(exception.getMessage().contains("status 401"));
        assertFalse(exception.getMessage().contains("invalid_client"));
        assertNull(exception.getCause());
    }

    private static IssuerDTO issuer() {
        IssuerDTO issuer = new IssuerDTO();
        issuer.setClient_id("client-1");
        issuer.setClient_alias("alias-1");
        return issuer;
    }
}
