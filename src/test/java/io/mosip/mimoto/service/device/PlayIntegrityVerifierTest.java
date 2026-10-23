package io.mosip.mimoto.service.device;

import io.mosip.mimoto.config.device.DeviceAttestationProperties;
import io.mosip.mimoto.dto.device.PlayIntegrityDecodeResponse;
import io.mosip.mimoto.dto.device.PlayIntegrityDecodeResponse.AppIntegrity;
import io.mosip.mimoto.dto.device.PlayIntegrityDecodeResponse.DeviceIntegrity;
import io.mosip.mimoto.dto.device.PlayIntegrityDecodeResponse.RequestDetails;
import io.mosip.mimoto.dto.device.PlayIntegrityDecodeResponse.TokenPayloadExternal;
import io.mosip.mimoto.exception.DeviceAttestationException;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

public class PlayIntegrityVerifierTest {

    private static final String PACKAGE = "io.mosip.residentapp";
    // SHA-256 of a signing certificate as the verdict reports it (web-safe base64) and as Play Console shows it (hex)
    private static final String DIGEST = "Gfbh3GqA42jJsiagFSdbC8IpZh2-Q-1vxM_Wy8GL2kw";
    private static final String DIGEST_HEX = "19:F6:E1:DC:6A:80:E3:68:C9:B2:26:A0:15:27:5B:0B:C2:29:66:1D:BE:43:ED:6F:C4:CF:D6:CB:C1:8B:DA:4C";
    private static final String NONCE = "aUupWQobGoLYwqhWcZwHdd1o0yRETcYn1qReCBMK3LA";
    private static final Instant NOW = Instant.parse("2026-10-12T10:00:00Z");

    private RestTemplate restTemplate;
    private PlayIntegrityVerifier verifier;
    private DeviceAttestationProperties properties;

    @Before
    public void setUp() {
        restTemplate = mock(RestTemplate.class);
        GoogleServiceAccountTokenProvider tokenProvider = mock(GoogleServiceAccountTokenProvider.class);
        when(tokenProvider.getAccessToken(PlayIntegrityVerifier.SCOPE)).thenReturn("google-access-token");
        properties = new DeviceAttestationProperties();
        properties.getAndroid().setPackageName(PACKAGE);
        properties.getAndroid().setCertSha256Digests(List.of(DIGEST));
        verifier = new PlayIntegrityVerifier(restTemplate, tokenProvider, properties, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private static TokenPayloadExternal payload(String requestPackage, String nonce, Instant issued, String appVerdict,
                                                String appPackage, List<String> digests, List<String> deviceVerdicts) {
        return new TokenPayloadExternal(
                new RequestDetails(requestPackage, nonce, String.valueOf(issued.toEpochMilli())),
                new AppIntegrity(appVerdict, appPackage, digests, "42"),
                new DeviceIntegrity(deviceVerdicts));
    }

    private static TokenPayloadExternal genuine() {
        return payload(PACKAGE, NONCE, NOW.minusSeconds(5), "PLAY_RECOGNIZED", PACKAGE, List.of(DIGEST),
                List.of("MEETS_BASIC_INTEGRITY", "MEETS_DEVICE_INTEGRITY"));
    }

    private void googleReturns(TokenPayloadExternal payload) {
        when(restTemplate.postForObject(eq(PlayIntegrityVerifier.DECODE_URL), any(HttpEntity.class),
                eq(PlayIntegrityDecodeResponse.class), eq(PACKAGE)))
                .thenReturn(new PlayIntegrityDecodeResponse(payload));
    }

    private void assertRejected(TokenPayloadExternal payload) {
        googleReturns(payload);
        DeviceAttestationException e = assertThrows(DeviceAttestationException.class, () -> verifier.verify("token", NONCE));
        assertEquals("attestation_failed", e.getErrorCode());
    }

    @Test
    @SuppressWarnings("unchecked")
    public void should_acceptAndSummarise_when_verdictIsGenuineAndBound() {
        googleReturns(genuine());

        Map<String, Object> summary = verifier.verify("token", NONCE);

        assertEquals("PLAY_RECOGNIZED", summary.get("appRecognitionVerdict"));
        assertEquals(List.of("MEETS_BASIC_INTEGRITY", "MEETS_DEVICE_INTEGRITY"), summary.get("deviceRecognitionVerdict"));
        ArgumentCaptor<HttpEntity> request = ArgumentCaptor.forClass(HttpEntity.class);
        verify(restTemplate).postForObject(eq(PlayIntegrityVerifier.DECODE_URL), request.capture(), eq(PlayIntegrityDecodeResponse.class), eq(PACKAGE));
        assertEquals(Map.of("integrityToken", "token"), request.getValue().getBody());
        assertEquals("Bearer google-access-token", request.getValue().getHeaders().getFirst("Authorization"));
    }

    @Test
    public void should_reject_when_nonceDoesNotMatch() {
        assertRejected(payload(PACKAGE, "other-nonce", NOW, "PLAY_RECOGNIZED", PACKAGE, List.of(DIGEST), List.of("MEETS_DEVICE_INTEGRITY")));
    }

    @Test
    public void should_accept_when_googlePadsNonce() {
        googleReturns(payload(PACKAGE, NONCE + "=", NOW, "PLAY_RECOGNIZED", PACKAGE, List.of(DIGEST),
                List.of("MEETS_DEVICE_INTEGRITY")));

        assertEquals("PLAY_RECOGNIZED", verifier.verify("token", NONCE).get("appRecognitionVerdict"));
    }

    @Test
    public void should_reject_when_nonceMissingOrMalformed() {
        for (String nonce : new String[]{null, "", NONCE + "==", NONCE + "!"}) {
            assertRejected(payload(PACKAGE, nonce, NOW, "PLAY_RECOGNIZED", PACKAGE, List.of(DIGEST),
                    List.of("MEETS_DEVICE_INTEGRITY")));
        }
    }

    @Test
    public void should_stillRejectUnrecognizedApp_when_googlePadsNonce() {
        googleReturns(payload(PACKAGE, NONCE + "=", NOW, "UNRECOGNIZED_VERSION", PACKAGE, List.of(DIGEST),
                List.of("MEETS_DEVICE_INTEGRITY")));

        DeviceAttestationException e = assertThrows(DeviceAttestationException.class,
                () -> verifier.verify("token", NONCE));
        assertTrue(e.getMessage().contains("app not recognized by Play"));
    }

    @Test
    public void should_reject_when_requestPackageDiffers() {
        assertRejected(payload("com.evil.app", NONCE, NOW, "PLAY_RECOGNIZED", PACKAGE, List.of(DIGEST), List.of("MEETS_DEVICE_INTEGRITY")));
    }

    @Test
    public void should_reject_when_appNotPlayRecognized() {
        assertRejected(payload(PACKAGE, NONCE, NOW, "UNRECOGNIZED_VERSION", PACKAGE, List.of(DIGEST), List.of("MEETS_DEVICE_INTEGRITY")));
    }

    @Test
    public void should_acceptUnrecognizedApp_when_showcaseExplicitlyEnabled() {
        properties.getAndroid().setAllowUnrecognizedApp(true);
        googleReturns(payload(PACKAGE, NONCE + "=", NOW, "UNRECOGNIZED_VERSION", PACKAGE, List.of(DIGEST),
                List.of("MEETS_DEVICE_INTEGRITY")));

        assertEquals("UNRECOGNIZED_VERSION", verifier.verify("token", NONCE).get("appRecognitionVerdict"));
    }

    @Test
    public void should_keepOtherChecksEnforced_when_showcaseEnabled() {
        properties.getAndroid().setAllowUnrecognizedApp(true);
        assertRejected(payload(PACKAGE, NONCE, NOW, "UNEVALUATED", PACKAGE, List.of(DIGEST), List.of("MEETS_DEVICE_INTEGRITY")));
        assertRejected(payload(PACKAGE, "wrong-nonce", NOW, "UNRECOGNIZED_VERSION", PACKAGE, List.of(DIGEST), List.of("MEETS_DEVICE_INTEGRITY")));
        assertRejected(payload(PACKAGE, NONCE, NOW, "UNRECOGNIZED_VERSION", "com.evil.app", List.of(DIGEST), List.of("MEETS_DEVICE_INTEGRITY")));
        assertRejected(payload(PACKAGE, NONCE, NOW, "UNRECOGNIZED_VERSION", PACKAGE, List.of("wrong-certificate"), List.of("MEETS_DEVICE_INTEGRITY")));
        assertRejected(payload(PACKAGE, NONCE, NOW, "UNRECOGNIZED_VERSION", PACKAGE, List.of(DIGEST), List.of("MEETS_BASIC_INTEGRITY")));
    }

    @Test
    public void should_reject_when_signingCertificateNotAllowed() {
        assertRejected(payload(PACKAGE, NONCE, NOW, "PLAY_RECOGNIZED", PACKAGE, List.of("re-signed"), List.of("MEETS_DEVICE_INTEGRITY")));
    }

    @Test
    public void should_matchDigest_when_configuredAsPlayConsoleHex() {
        properties.getAndroid().setCertSha256Digests(List.of(DIGEST_HEX));
        googleReturns(genuine());

        assertEquals("PLAY_RECOGNIZED", verifier.verify("token", NONCE).get("appRecognitionVerdict"));
    }

    @Test
    public void should_matchDigest_when_verdictPadsBase64() {
        googleReturns(payload(PACKAGE, NONCE, NOW, "PLAY_RECOGNIZED", PACKAGE, List.of(DIGEST + "="), List.of("MEETS_DEVICE_INTEGRITY")));

        assertEquals("PLAY_RECOGNIZED", verifier.verify("token", NONCE).get("appRecognitionVerdict"));
    }

    @Test
    public void should_normaliseDigestForms_when_comparing() {
        String hex = "19f6e1dc6a80e368c9b226a015275b0bc229661dbe43ed6fc4cfd6cbc18bda4c";
        assertEquals(hex, PlayIntegrityVerifier.digestHex(DIGEST));
        assertEquals(hex, PlayIntegrityVerifier.digestHex(DIGEST_HEX));
        assertEquals(hex, PlayIntegrityVerifier.digestHex(hex.toUpperCase()));
        assertNull(PlayIntegrityVerifier.digestHex("not-a-digest"));
        assertNull(PlayIntegrityVerifier.digestHex(""));
    }

    @Test
    public void should_reject_when_deviceVerdictNotAccepted() {
        assertRejected(payload(PACKAGE, NONCE, NOW, "PLAY_RECOGNIZED", PACKAGE, List.of(DIGEST), List.of("MEETS_BASIC_INTEGRITY")));
        assertRejected(payload(PACKAGE, NONCE, NOW, "PLAY_RECOGNIZED", PACKAGE, List.of(DIGEST), List.of()));
    }

    @Test
    public void should_reject_when_tokenTooOldOrFromFuture() {
        assertRejected(payload(PACKAGE, NONCE, NOW.minusSeconds(301), "PLAY_RECOGNIZED", PACKAGE, List.of(DIGEST), List.of("MEETS_DEVICE_INTEGRITY")));
        assertRejected(payload(PACKAGE, NONCE, NOW.plusSeconds(61), "PLAY_RECOGNIZED", PACKAGE, List.of(DIGEST), List.of("MEETS_DEVICE_INTEGRITY")));
    }

    @Test
    public void should_reject_when_verdictSectionMissing() {
        assertRejected(new TokenPayloadExternal(null, null, null));
    }

    @Test
    public void should_rejectWithoutCallingGoogle_when_notConfigured() {
        properties.getAndroid().setCertSha256Digests(List.of());

        assertThrows(DeviceAttestationException.class, () -> verifier.verify("token", NONCE));
        verifyNoInteractions(restTemplate);
    }

    @Test
    public void should_reportAttestationFailed_when_googleRejectsToken() {
        when(restTemplate.postForObject(anyString(), any(), any(Class.class), anyString()))
                .thenThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST));

        assertEquals("attestation_failed",
                assertThrows(DeviceAttestationException.class, () -> verifier.verify("token", NONCE)).getErrorCode());
    }

    @Test
    public void should_reportServerUnavailable_when_googleUnreachable() {
        when(restTemplate.postForObject(anyString(), any(), any(Class.class), anyString()))
                .thenThrow(new ResourceAccessException("timeout"));

        assertEquals("server_unavailable",
                assertThrows(DeviceAttestationException.class, () -> verifier.verify("token", NONCE)).getErrorCode());
    }
}
