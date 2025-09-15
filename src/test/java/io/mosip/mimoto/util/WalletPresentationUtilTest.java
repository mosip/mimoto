package io.mosip.mimoto.util;

import io.mosip.mimoto.dto.openid.VerifierDTO;
import io.mosip.openID4VP.authorizationRequest.Verifier;
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk;
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwks;
import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class WalletPresentationUtilTest {

    VerifierDTO verifierDTO;
    Map<String, Object> clientMetadata;

    @Before
    public void setUp() {
        clientMetadata = new HashMap<>(Map.of(
                "client_name", "Test Client",
                "logo_uri", "http://example.com/logo.png",
                "vp_formats", new HashMap<>(Map.of(
                        "jwt_vp", Map.of(
                                "alg", List.of("Ed25519Signature2020")
                        ))),
                "jwks", Map.of(
                        "keys", List.of(
                                Map.of("kty", "OKP", "use", "sig", "crv", "Ed25519", "x", "ed25519-x-value", "alg", "EdDSA", "kid", "key-id")
                        )
                )
        ));
        verifierDTO = new VerifierDTO("mock-client", List.of("https://injiverify.collab.mosip.net/redirect"), List.of("https://injiverify.collab.mosip.net/vp-submission"), clientMetadata);
    }

    @Test
    public void testMapToVerifierWithNullClientMetadata() {
        verifierDTO.setClientMetadata(null);
        Verifier verifier = WalletPresentationUtil.mapToVerifier(verifierDTO);

        assertNotNull(verifier);
        assertEquals("mock-client", verifier.getClientId());
        assertEquals(List.of("https://injiverify.collab.mosip.net/vp-submission"), verifier.getResponseUris());
        assertNull(verifier.getClientMetadata());
    }

    @Test
    public void testMapToVerifierWithValidClientMetadata() {
        Verifier verifier = WalletPresentationUtil.mapToVerifier(verifierDTO);

        assertNotNull(verifier);
        assertEquals("mock-client", verifier.getClientId());
        assertEquals(List.of("https://injiverify.collab.mosip.net/vp-submission"), verifier.getResponseUris());
        assertNotNull(verifier.getClientMetadata());
        Jwks jwks = verifier.getClientMetadata().getJwks();
        assertNotNull(jwks);
        assertEquals(1, jwks.getKeys().size());
        Jwk jwk = jwks.getKeys().get(0);
        assertEquals("OKP", jwk.getKty());
        assertEquals("sig", jwk.getUse());
        assertEquals("Ed25519", jwk.getCrv());
        assertEquals("ed25519-x-value", jwk.getX());
        assertNull(jwk.getY()); // Ed25519 does not use 'y'
        assertEquals("EdDSA", jwk.getAlg());
        assertEquals("key-id", jwk.getKid());
    }

    @Test
    public void testMapToVerifierWithInvalidJwksType() {
        clientMetadata.put("jwks", "invalid-type");
        verifierDTO.setClientMetadata(clientMetadata);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
                WalletPresentationUtil.mapToVerifier(verifierDTO)
        );

        assertEquals("'jwks' must be a Map<String, Object>", exception.getMessage());
    }

    @Test
    public void testMapToVerifierWithInvalidKeysType() {
        clientMetadata.put("jwks", Map.of("keys", "invalid-type"));
        verifierDTO.setClientMetadata(clientMetadata);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
                WalletPresentationUtil.mapToVerifier(verifierDTO)
        );

        assertEquals("'keys' must be a List<Map<String, String>>", exception.getMessage());
    }

    @Test
    public void testMapToVerifierWithNullJwks() {
        clientMetadata.put("jwks", null);

        Verifier verifier = WalletPresentationUtil.mapToVerifier(verifierDTO);

        assertNotNull(verifier);
        assertEquals("mock-client", verifier.getClientId());
        assertEquals(List.of("https://injiverify.collab.mosip.net/vp-submission"), verifier.getResponseUris());
        assertNotNull(verifier.getClientMetadata());
        assertNull(verifier.getClientMetadata().getJwks());
    }
}