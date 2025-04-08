package io.mosip.mimoto.util;

import com.nimbusds.jwt.SignedJWT;
import io.mosip.mimoto.model.SigningAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import static org.junit.Assert.*;

@Slf4j
public class JwtGeneratorUtilTest {

    @BeforeClass
    public static void setupProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private String createAccessTokenWithNonce(String nonce) throws Exception {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"HS256\"}".getBytes());
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(("{\"c_nonce\":\"" + nonce + "\"}").getBytes());
        String signature = Base64.getUrlEncoder().withoutPadding().encodeToString("dummy".getBytes());
        return header + "." + payload + "." + signature;
    }

    @Test
    public void shouldGenerateJWTForRS256Successfully() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        String accessToken = createAccessTokenWithNonce("nonce-rs256");
        List<Object> expectedClaims = Arrays.asList("client-id", "audience", "nonce-rs256");

        String jwt = JwtGeneratorUtil.generateJwtUsingDBKeys(
                SigningAlgorithm.RS256,
                "audience",
                "client-id",
                accessToken,
                keyPair.getPublic().getEncoded(),
                keyPair.getPrivate().getEncoded()
        );

        SignedJWT signedJWT = SignedJWT.parse(jwt);
        List<Object> actualClaims = Arrays.asList(
                signedJWT.getJWTClaimsSet().getSubject(),
                signedJWT.getJWTClaimsSet().getAudience().get(0),
                signedJWT.getJWTClaimsSet().getStringClaim("nonce")
        );

        assertEquals(expectedClaims, actualClaims);
        assertEquals(18000, diffInSeconds(signedJWT.getJWTClaimsSet().getIssueTime(), signedJWT.getJWTClaimsSet().getExpirationTime()));
    }

    @Test
    public void shouldGenerateJWTForES256Successfully() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = generator.generateKeyPair();
        String accessToken = createAccessTokenWithNonce("nonce-es256");
        List<Object> expectedClaims = Arrays.asList("client-id", "audience", "nonce-es256");

        String jwt = JwtGeneratorUtil.generateJwtUsingDBKeys(
                SigningAlgorithm.ES256,
                "audience",
                "client-id",
                accessToken,
                keyPair.getPublic().getEncoded(),
                keyPair.getPrivate().getEncoded()
        );

        SignedJWT signedJWT = SignedJWT.parse(jwt);
        List<Object> actualClaims = Arrays.asList(
                signedJWT.getJWTClaimsSet().getSubject(),
                signedJWT.getJWTClaimsSet().getAudience().get(0),
                signedJWT.getJWTClaimsSet().getStringClaim("nonce")
        );

        assertEquals(expectedClaims, actualClaims);
        assertEquals(18000, diffInSeconds(signedJWT.getJWTClaimsSet().getIssueTime(), signedJWT.getJWTClaimsSet().getExpirationTime()));
    }

    @Test
    public void shouldGenerateJWTForES256kSuccessfully() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
        generator.initialize(new ECGenParameterSpec("secp256k1"));
        KeyPair keyPair = generator.generateKeyPair();
        String accessToken = createAccessTokenWithNonce("nonce-es256k");
        List<Object> expectedClaims = Arrays.asList("client-id", "audience", "nonce-es256k");

        String jwt = JwtGeneratorUtil.generateJwtUsingDBKeys(
                SigningAlgorithm.ES256K,
                "audience",
                "client-id",
                accessToken,
                keyPair.getPublic().getEncoded(),
                keyPair.getPrivate().getEncoded()
        );

        SignedJWT signedJWT = SignedJWT.parse(jwt);
        List<Object> actualClaims = Arrays.asList(
                signedJWT.getJWTClaimsSet().getSubject(),
                signedJWT.getJWTClaimsSet().getAudience().get(0),
                signedJWT.getJWTClaimsSet().getStringClaim("nonce")
        );

        assertEquals(expectedClaims, actualClaims);
        assertEquals(18000, diffInSeconds(signedJWT.getJWTClaimsSet().getIssueTime(), signedJWT.getJWTClaimsSet().getExpirationTime()));
    }

    @Test
    public void shouldGenerateJWTForED25519Successfully() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519", "BC");
        KeyPair keyPair = generator.generateKeyPair();
        String accessToken = createAccessTokenWithNonce("nonce-ed25519");
        List<Object> expectedClaims = Arrays.asList("client-id", "audience", "nonce-ed25519");

        String jwt = JwtGeneratorUtil.generateJwtUsingDBKeys(
                SigningAlgorithm.ED25519,
                "audience",
                "client-id",
                accessToken,
                keyPair.getPublic().getEncoded(),
                keyPair.getPrivate().getEncoded()
        );

        SignedJWT signedJWT = SignedJWT.parse(jwt);
        List<Object> actualClaims = Arrays.asList(
                signedJWT.getJWTClaimsSet().getSubject(),
                signedJWT.getJWTClaimsSet().getAudience().get(0),
                signedJWT.getJWTClaimsSet().getStringClaim("nonce")
        );

        assertEquals(expectedClaims, actualClaims);
        assertEquals(18000, diffInSeconds(signedJWT.getJWTClaimsSet().getIssueTime(), signedJWT.getJWTClaimsSet().getExpirationTime()));
    }

    @Test(expected = Exception.class)
    public void shouldThrowExceptionIfAccessTokenIsNotInJWTFormat() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        JwtGeneratorUtil.generateJwtUsingDBKeys(
                SigningAlgorithm.RS256,
                "aud",
                "client",
                "invalid-nonce",
                keyPair.getPublic().getEncoded(),
                keyPair.getPrivate().getEncoded()
        );
    }

    public long diffInSeconds(Date issuedAt, Date expiresAt) {
        return (expiresAt.getTime() - issuedAt.getTime()) / 1000;
    }
}
