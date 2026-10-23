package io.mosip.mimoto.service.device;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.mosip.mimoto.config.device.DeviceAttestationProperties;
import io.mosip.mimoto.exception.DeviceAttestationException;
import io.mosip.mimoto.model.DeviceRegistration;
import io.mosip.mimoto.model.DeviceRegistrationStatus;
import io.mosip.mimoto.repository.DeviceRegistrationRepository;
import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.Optional;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

public class DeviceProofVerifierTest {

    private static final Instant NOW = Instant.parse("2026-10-12T10:00:00Z");
    private static final String PATH = "/v1/mimoto/v2/get-token/issuerX";
    private static final String HTU = "https://api.example.net" + PATH;
    private static final byte[] BODY = "grant_type=authorization_code&code=PRIYA_CODE".getBytes(StandardCharsets.UTF_8);

    private DeviceRegistrationRepository repository;
    private DeviceNonceService nonceService;
    private DeviceProofVerifier verifier;
    private ECKey deviceKey;
    private String thumbprint;
    private DeviceRegistration registration;

    @Before
    public void setUp() throws Exception {
        repository = mock(DeviceRegistrationRepository.class);
        nonceService = new DeviceNonceService(new InMemoryDeviceNonceStore(), new DeviceAttestationProperties());
        verifier = new DeviceProofVerifier(repository, nonceService, new DeviceAttestationProperties(), Clock.fixed(NOW, ZoneOffset.UTC));
        deviceKey = new ECKeyGenerator(Curve.P_256).generate();
        thumbprint = deviceKey.computeThumbprint().toString();
        registration = new DeviceRegistration();
        registration.setJwkThumbprint(thumbprint);
        registration.setPublicKeyJwk(deviceKey.toPublicJWK().toJSONString());
        registration.setStatus(DeviceRegistrationStatus.ACTIVE);
        when(repository.findById(thumbprint)).thenReturn(Optional.of(registration));
    }

    private JWTClaimsSet.Builder validClaims(String nonce) {
        return new JWTClaimsSet.Builder()
                .claim("nonce", nonce)
                .claim("htm", "POST")
                .claim("htu", HTU)
                .claim("req_hash", DeviceProofVerifier.sha256(BODY))
                .issueTime(Date.from(NOW.minusSeconds(2)))
                .expirationTime(Date.from(NOW.plusSeconds(50)));
    }

    private String sign(ECKey key, JWSHeader header, JWTClaimsSet claims) throws Exception {
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(key));
        return jwt.serialize();
    }

    private JWSHeader validHeader() {
        return new JWSHeader.Builder(JWSAlgorithm.ES256).type(DeviceProofVerifier.PROOF_TYPE).keyID(thumbprint).build();
    }

    private String proof(Consumer<JWTClaimsSet.Builder> change) throws Exception {
        JWTClaimsSet.Builder claims = validClaims(nonceService.issue());
        change.accept(claims);
        return sign(deviceKey, validHeader(), claims.build());
    }

    private void assertRejected(String code, String proof, byte[] body) {
        DeviceAttestationException e = assertThrows(DeviceAttestationException.class,
                () -> verifier.verify(proof, "POST", PATH, body));
        assertEquals(code, e.getErrorCode());
    }

    @Test
    public void should_acceptAndTouchLastSeen_when_proofValid() throws Exception {
        assertEquals(thumbprint, verifier.verify(proof(c -> { }), "POST", PATH, BODY));
        verify(repository).touchLastSeen(eq(thumbprint), eq(NOW), eq(NOW.minusSeconds(3600)));
    }

    @Test
    public void should_accept_when_htuHostDiffersButPathMatches() throws Exception {
        String proof = proof(c -> c.claim("htu", "https://internal-ingress:8443" + PATH));
        assertEquals(thumbprint, verifier.verify(proof, "POST", PATH, BODY));
    }

    @Test
    public void should_reject_when_proofReplayed() throws Exception {
        String proof = proof(c -> { });
        verifier.verify(proof, "POST", PATH, BODY);

        assertRejected("invalid_device_proof", proof, BODY);
    }

    @Test
    public void should_reject_when_proofMovedToDifferentBody() throws Exception {
        byte[] swapped = "grant_type=authorization_code&code=BOT_CODE".getBytes(StandardCharsets.UTF_8);
        String proof = proof(c -> { });

        assertRejected("invalid_device_proof", proof, swapped);
        // the failed attempt does not burn the nonce, so the genuine request still succeeds
        assertEquals(thumbprint, verifier.verify(proof, "POST", PATH, BODY));
    }

    @Test
    public void should_reject_when_missingOrMalformed() {
        assertRejected("invalid_device_proof", null, BODY);
        assertRejected("invalid_device_proof", "", BODY);
        assertRejected("invalid_device_proof", "not.a.jwt", BODY);
    }

    @Test
    public void should_reject_when_headerWrong() throws Exception {
        JWTClaimsSet claims = validClaims(nonceService.issue()).build();
        assertRejected("invalid_device_proof",
                sign(deviceKey, new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("dpop+jwt")).keyID(thumbprint).build(), claims), BODY);
        assertRejected("invalid_device_proof",
                sign(deviceKey, new JWSHeader.Builder(JWSAlgorithm.ES256).type(DeviceProofVerifier.PROOF_TYPE).build(), claims), BODY);
    }

    @Test
    public void should_reportNotRegistered_when_kidUnknown() throws Exception {
        ECKey stranger = new ECKeyGenerator(Curve.P_256).generate();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).type(DeviceProofVerifier.PROOF_TYPE)
                .keyID(stranger.computeThumbprint().toString()).build();
        when(repository.findById(anyString())).thenReturn(Optional.empty());

        assertRejected("device_not_registered", sign(stranger, header, validClaims(nonceService.issue()).build()), BODY);
    }

    @Test
    public void should_reject_when_deviceRevoked() throws Exception {
        registration.setStatus(DeviceRegistrationStatus.REVOKED);
        assertRejected("device_revoked", proof(c -> { }), BODY);
    }

    @Test
    public void should_reject_when_signedByAnotherKeyUnderRegisteredKid() throws Exception {
        ECKey attacker = new ECKeyGenerator(Curve.P_256).generate();
        assertRejected("invalid_device_proof", sign(attacker, validHeader(), validClaims(nonceService.issue()).build()), BODY);
    }

    @Test
    public void should_accept_when_deviceClockIsOff() throws Exception {
        Instant deviceClock = NOW.minusSeconds(3 * 3600);
        String proof = proof(c -> c.issueTime(Date.from(deviceClock)).expirationTime(Date.from(deviceClock.plusSeconds(60))));

        assertEquals(thumbprint, verifier.verify(proof, "POST", PATH, BODY));
    }

    @Test
    public void should_reject_when_lifetimeInvalid() throws Exception {
        assertRejected("invalid_device_proof", proof(c -> c.expirationTime(Date.from(NOW.plusSeconds(3600)))), BODY);
        assertRejected("invalid_device_proof", proof(c -> c.expirationTime(Date.from(NOW.minusSeconds(5)))), BODY);
        assertRejected("invalid_device_proof", proof(c -> c.expirationTime(null)), BODY);
        assertRejected("invalid_device_proof", proof(c -> c.issueTime(null)), BODY);
    }

    @Test
    public void should_reject_when_methodOrPathDiffers() throws Exception {
        assertRejected("invalid_device_proof", proof(c -> c.claim("htm", "GET")), BODY);
        assertRejected("invalid_device_proof", proof(c -> c.claim("htu", "https://api.example.net/v1/mimoto/get-token/issuerX")), BODY);
        assertRejected("invalid_device_proof", proof(c -> c.claim("htu", "not a uri")), BODY);
    }

    @Test
    public void should_reject_when_nonceNotIssued() throws Exception {
        assertRejected("invalid_device_proof", proof(c -> c.claim("nonce", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")), BODY);
        verify(repository, never()).touchLastSeen(any(), any(), any());
    }
}
