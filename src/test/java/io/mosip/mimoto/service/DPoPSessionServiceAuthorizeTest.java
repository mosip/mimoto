package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.dpop.DPoPSession;
import io.mosip.mimoto.dto.dpop.IssuerAuthorizeRequest;
import io.mosip.mimoto.dto.dpop.IssuerAuthorizeResponse;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerConfiguration;
import io.mosip.mimoto.dto.pkce.PkceSession;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.util.PkceUtil;
import org.junit.Test;
import org.springframework.mock.web.MockHttpSession;

import java.util.List;
import java.util.Map;

import static io.mosip.mimoto.util.TestUtilities.getCredentialIssuerConfigurationResponseDto;
import static io.mosip.mimoto.util.TestUtilities.getIssuerDTO;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class DPoPSessionServiceAuthorizeTest {

    private static final String SCOPE = "CredentialType1_vc_ldp";

    @Test
    public void should_includePkceAndDPoPJkt_when_authorizationUrlIsBuilt() throws Exception {
        PkceSessionManager pkceSessionManager = new PkceSessionManager();
        DPoPSessionService service = serviceWithMocks(pkceSessionManager);
        MockHttpSession httpSession = new MockHttpSession();

        IssuerAuthorizeResponse response = createAuthorizationUrl(service, httpSession);

        assertTrue(response.getAuthorizationUrl().startsWith("https://dev/authorize?"));
        assertTrue(response.getAuthorizationUrl().contains("client_id=123"));
        assertTrue(response.getAuthorizationUrl().contains("dpop_jkt=thumbprint"));
        assertTrue(response.getAuthorizationUrl().contains("code_challenge_method=S256"));
        assertTrue(response.getAuthorizationUrl().contains("code_challenge="));
        assertTrue(response.getAuthorizationUrl().contains("scope=CredentialType1_vc_ldp"));
        assertTrue(response.getAuthorizationUrl().contains("response_type=code"));
        assertTrue(response.getAuthorizationUrl().contains("ui_locales=en"));
        assertTrue(response.getAuthorizationUrl().contains("state=" + java.net.URLEncoder.encode(response.getState(), java.nio.charset.StandardCharsets.UTF_8)));
        assertEquals(43, response.getState().length());

        DPoPSession storedDPoP = service.find(httpSession, response.getState());
        assertNotNull(storedDPoP);
        assertEquals("ES256", storedDPoP.getAlg());

        PkceSession storedPkce = pkceSessionManager.find(httpSession, response.getState());
        assertNotNull(storedPkce);
        assertEquals(43, storedPkce.getCodeVerifier().length());
        assertEquals("https://injiweb.example.com/redirect", storedPkce.getRedirectUri());
        assertTrue(response.getAuthorizationUrl().contains("code_challenge=" + PkceUtil.s256Challenge(storedPkce.getCodeVerifier())));
    }

    @Test
    public void should_includeStoredPkceAndRedirectUri_when_authorizationCodeParamsAreBuilt() throws Exception {
        PkceSessionManager pkceSessionManager = new PkceSessionManager();
        DPoPSessionService service = serviceWithMocks(pkceSessionManager);
        MockHttpSession httpSession = new MockHttpSession();
        IssuerAuthorizeResponse response = createAuthorizationUrl(service, httpSession);

        Map<String, String> params = service.authorizationCodeParams(httpSession, response.getState(), "auth-code", "LocalMockid");

        PkceSession storedPkce = pkceSessionManager.find(httpSession, response.getState());
        assertEquals("auth-code", params.get("code"));
        assertEquals(storedPkce.getCodeVerifier(), params.get("code_verifier"));
        assertEquals("https://injiweb.example.com/redirect", params.get("redirect_uri"));
        assertEquals("authorization_code", params.get("grant_type"));
        assertEquals("LocalMockid", params.get("issuer"));
        assertEquals(response.getState(), params.get("state"));
    }

    @Test
    public void should_throwInvalidRequest_when_issuerIdIsBlank() throws Exception {
        DPoPSessionService service = serviceWithMocks();
        MockHttpSession httpSession = new MockHttpSession();
        IssuerAuthorizeResponse response = createAuthorizationUrl(service, httpSession);

        InvalidRequestException exception = assertThrows(InvalidRequestException.class,
                () -> service.authorizationCodeParams(httpSession, response.getState(), "auth-code", " "));
        assertEquals("issuerId cannot be blank", exception.getErrorText());
    }

    @Test
    public void should_throwInvalidRequest_when_authorizationCodeIsBlank() throws Exception {
        DPoPSessionService service = serviceWithMocks();
        MockHttpSession httpSession = new MockHttpSession();
        IssuerAuthorizeResponse response = createAuthorizationUrl(service, httpSession);

        assertThrows(InvalidRequestException.class,
                () -> service.authorizationCodeParams(httpSession, response.getState(), " ", "LocalMockid"));
    }

    @Test
    public void should_keepBothDPoPStates_when_concurrentStoresComplete() throws Exception {
        PkceSessionManager pkceSessionManager = new PkceSessionManager();
        DPoPSessionService service = serviceWithMocks(pkceSessionManager);
        MockHttpSession httpSession = new MockHttpSession();
        DPoPSession first = DPoPSession.builder()
                .state("state-a")
                .build();
        DPoPSession second = DPoPSession.builder()
                .state("state-b")
                .build();

        Thread firstStore = new Thread(() -> service.store(httpSession, first));
        Thread secondStore = new Thread(() -> service.store(httpSession, second));
        firstStore.start();
        secondStore.start();
        firstStore.join();
        secondStore.join();

        assertNotNull(service.find(httpSession, "state-a"));
        assertNotNull(service.find(httpSession, "state-b"));

        pkceSessionManager.store(httpSession, PkceSession.builder()
                .state("state-a")
                .codeVerifier("verifier-a")
                .redirectUri("https://injiweb.example.com/redirect")
                .build());

        service.remove(httpSession, "state-a");
        assertNull(service.find(httpSession, "state-a"));
        assertNull(pkceSessionManager.find(httpSession, "state-a"));
        assertNotNull(service.find(httpSession, "state-b"));
    }

    private static IssuerAuthorizeResponse createAuthorizationUrl(DPoPSessionService service, MockHttpSession httpSession) {
        return service.createAuthorizationUrl(httpSession, authorizeRequest(),
                issuerConfiguration(), issuer(), SCOPE);
    }

    private static DPoPSessionService serviceWithMocks() throws Exception {
        return serviceWithMocks(new PkceSessionManager());
    }

    private static DPoPSessionService serviceWithMocks(PkceSessionManager pkceSessionManager) throws Exception {
        DPoPManager dPoPManager = mock(DPoPManager.class);
        DPoPSessionService service = new DPoPSessionService(dPoPManager, pkceSessionManager);

        when(dPoPManager.selectAlgorithm(any())).thenReturn("ES256");
        stubCreateSession(dPoPManager);
        when(dPoPManager.jwkThumbprint(any())).thenReturn("thumbprint");
        return service;
    }

    private static void stubCreateSession(DPoPManager dPoPManager) throws Exception {
        when(dPoPManager.createSession(any(), eq("ES256"), any()))
                .thenAnswer(invocation -> DPoPSession.builder()
                        .state(invocation.getArgument(0))
                        .alg("ES256")
                        .jwkJson("{}")
                        .tokenHtu(invocation.getArgument(2))
                        .build());
    }

    private static CredentialIssuerConfiguration issuerConfiguration() {
        return getCredentialIssuerConfigurationResponseDto("LocalMock", "CredentialType1", List.of());
    }

    private static IssuerDTO issuer() {
        return getIssuerDTO("LocalMock");
    }

    private static IssuerAuthorizeRequest authorizeRequest() {
        IssuerAuthorizeRequest request = new IssuerAuthorizeRequest();
        request.setRedirectUri("https://injiweb.example.com/redirect");
        request.setCredentialConfigurationId("CredentialType1");
        request.setUiLocales("en");
        return request;
    }
}
