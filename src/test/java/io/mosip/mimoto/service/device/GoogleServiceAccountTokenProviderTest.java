package io.mosip.mimoto.service.device;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import io.mosip.mimoto.config.device.DeviceAttestationProperties;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

public class GoogleServiceAccountTokenProviderTest {

    private static final String SCOPE = "https://www.googleapis.com/auth/playintegrity";

    private RestTemplate restTemplate;
    private KeyPair keyPair;
    private DeviceAttestationProperties properties;
    private final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-10-12T10:00:00Z"));
    private final Clock clock = new Clock() {
        public java.time.ZoneId getZone() { return ZoneOffset.UTC; }
        public Clock withZone(java.time.ZoneId zone) { return this; }
        public Instant instant() { return now.get(); }
    };

    @Before
    public void setUp() throws Exception {
        restTemplate = mock(RestTemplate.class);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
        String pem = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(keyPair.getPrivate().getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
        Path keyFile = Files.createTempFile("sa", ".json");
        keyFile.toFile().deleteOnExit();
        Files.writeString(keyFile, new ObjectMapper().writeValueAsString(Map.of(
                "type", "service_account",
                "client_email", "verifier@project.iam.gserviceaccount.com",
                "private_key_id", "key-1",
                "private_key", pem,
                "token_uri", "https://oauth2.googleapis.com/token")));
        properties = new DeviceAttestationProperties();
        properties.getGoogle().setServiceAccountKeyPath(keyFile.toString());
    }

    private GoogleServiceAccountTokenProvider provider() {
        return new GoogleServiceAccountTokenProvider(restTemplate, properties, new ObjectMapper(), clock);
    }

    private void tokenEndpointReturns(String token) {
        when(restTemplate.postForObject(eq(GoogleServiceAccountTokenProvider.TOKEN_ENDPOINT), any(), eq(GoogleServiceAccountTokenProvider.TokenResponse.class)))
                .thenReturn(new GoogleServiceAccountTokenProvider.TokenResponse(token, 3600, "Bearer"));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void should_postSignedJwtBearerAssertion_when_tokenRequested() throws Exception {
        tokenEndpointReturns("access-1");

        assertEquals("access-1", provider().getAccessToken(SCOPE));

        ArgumentCaptor<HttpEntity> request = ArgumentCaptor.forClass(HttpEntity.class);
        verify(restTemplate).postForObject(eq("https://oauth2.googleapis.com/token"), request.capture(), any(Class.class));
        MultiValueMap<String, String> form = (MultiValueMap<String, String>) request.getValue().getBody();
        assertEquals("urn:ietf:params:oauth:grant-type:jwt-bearer", form.getFirst("grant_type"));

        SignedJWT assertion = SignedJWT.parse(form.getFirst("assertion"));
        assertTrue(assertion.verify(new RSASSAVerifier((RSAPublicKey) keyPair.getPublic())));
        assertEquals(JWSAlgorithm.RS256, assertion.getHeader().getAlgorithm());
        assertEquals("JWT", assertion.getHeader().getType().toString());
        assertEquals("key-1", assertion.getHeader().getKeyID());
        assertEquals("verifier@project.iam.gserviceaccount.com", assertion.getJWTClaimsSet().getIssuer());
        assertEquals(SCOPE, assertion.getJWTClaimsSet().getStringClaim("scope"));
        assertEquals("https://oauth2.googleapis.com/token", assertion.getJWTClaimsSet().getAudience().get(0));
        long lifetime = assertion.getJWTClaimsSet().getExpirationTime().getTime() - assertion.getJWTClaimsSet().getIssueTime().getTime();
        assertEquals(3600_000, lifetime);
    }

    @Test
    public void should_reuseCachedToken_when_notNearExpiry() {
        tokenEndpointReturns("access-1");
        GoogleServiceAccountTokenProvider provider = provider();

        provider.getAccessToken(SCOPE);
        now.set(now.get().plusSeconds(3000));
        assertEquals("access-1", provider.getAccessToken(SCOPE));

        verify(restTemplate, times(1)).postForObject(anyString(), any(), any(Class.class));
    }

    @Test
    public void should_fetchNewToken_when_cachedTokenNearExpiry() {
        tokenEndpointReturns("access-1");
        GoogleServiceAccountTokenProvider provider = provider();
        provider.getAccessToken(SCOPE);

        tokenEndpointReturns("access-2");
        now.set(now.get().plusSeconds(3550));
        assertEquals("access-2", provider.getAccessToken(SCOPE));
    }

    @Test
    public void should_fail_when_keyPathNotConfigured() {
        properties.getGoogle().setServiceAccountKeyPath("");

        assertThrows(IllegalStateException.class, () -> provider().getAccessToken(SCOPE));
        verifyNoInteractions(restTemplate);
    }

    @Test
    public void should_fail_when_tokenEndpointReturnsNoToken() {
        when(restTemplate.postForObject(anyString(), any(), any(Class.class))).thenReturn(null);

        assertThrows(IllegalStateException.class, () -> provider().getAccessToken(SCOPE));
    }
}
