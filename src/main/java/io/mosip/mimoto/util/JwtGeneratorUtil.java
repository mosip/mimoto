package io.mosip.mimoto.util;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.*;
import com.nimbusds.jose.util.Base64URL;
import io.mosip.mimoto.model.SigningAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.interfaces.*;
import java.util.*;
import java.util.Arrays;


@Slf4j
public class JwtGeneratorUtil {

    private static final Provider BC_PROVIDER = new BouncyCastleProvider();

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BC_PROVIDER);
        }
    }

    public static String generateJwtUsingDBKeys(SigningAlgorithm algorithm, String audience, String clientId, String accessToken, byte[] publicKeyBytes, byte[] privateKeyBytes) throws Exception {
        KeyPair keyPair = KeyGenerationUtil.getKeyPairFromDBStoredKeys(algorithm, publicKeyBytes, privateKeyBytes);
        JWK jwk = generateJwk(algorithm, keyPair);
        JWSSigner signer = createSigner(algorithm, jwk);

        JWTClaimsSet claimsSet = createClaims(clientId, audience, accessToken);
        JWSHeader header = new JWSHeader.Builder(algorithm.getJWSAlgorithm())
                .type(new JOSEObjectType("openid4vci-proof+jwt"))
                .jwk(jwk.toPublicJWK())
                .build();

        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }

    private static JWTClaimsSet createClaims(String clientId, String audience, String accessToken) throws java.text.ParseException {
        long nowSeconds = System.currentTimeMillis() / 1000;
        Date issuedAt = new Date(nowSeconds * 1000);
        Date expiresAt = new Date((nowSeconds + 18000) * 1000);
        String nonce = SignedJWT.parse(accessToken).getJWTClaimsSet().getStringClaim("c_nonce");

        return new JWTClaimsSet.Builder()
                .subject(clientId)
                .audience(audience)
                .issuer(clientId)
                .issueTime(issuedAt)
                .expirationTime(expiresAt)
                .claim("nonce", nonce)
                .build();
    }


    private static JWK generateJwk(SigningAlgorithm algorithm, KeyPair keyPair) {
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        return switch (algorithm) {
            case RS256 -> new RSAKey.Builder((RSAPublicKey) publicKey)
                    .privateKey((RSAPrivateKey) privateKey)
                    .algorithm(JWSAlgorithm.RS256)
                    .keyUse(KeyUse.SIGNATURE)
                    .build();

            case ES256 -> new ECKey.Builder(Curve.P_256, (ECPublicKey) publicKey)
                    .privateKey((ECPrivateKey) privateKey)
                    .algorithm(JWSAlgorithm.ES256)
                    .keyUse(KeyUse.SIGNATURE)
                    .build();

            case ES256K -> new ECKey.Builder(Curve.SECP256K1, (ECPublicKey) publicKey)
                    .privateKey((ECPrivateKey) privateKey)
                    .algorithm(JWSAlgorithm.ES256K)
                    .keyUse(KeyUse.SIGNATURE)
                    .build();

            case ED25519 -> {
                EdECPublicKey edECPublicKey = (EdECPublicKey) publicKey;
                EdECPrivateKey edECPrivateKey = (EdECPrivateKey) privateKey;

                byte[] x = Arrays.copyOfRange(edECPublicKey.getEncoded(), edECPublicKey.getEncoded().length - 32, edECPublicKey.getEncoded().length);
                byte[] d = Arrays.copyOfRange(edECPrivateKey.getEncoded(), edECPrivateKey.getEncoded().length - 32, edECPrivateKey.getEncoded().length);

                yield new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(x))
                        .d(Base64URL.encode(d))
                        .algorithm(JWSAlgorithm.EdDSA)
                        .keyUse(KeyUse.SIGNATURE)
                        .build();
            }
        };
    }

    private static JWSSigner createSigner(SigningAlgorithm algorithm, JWK jwk) throws JOSEException {
        return switch (algorithm) {
            case RS256 -> {
                RSASSASigner signer = new RSASSASigner((RSAKey) jwk);
                signer.getJCAContext().setProvider(BC_PROVIDER);
                yield signer;
            }
            case ES256, ES256K -> {
                ECDSASigner signer = new ECDSASigner((ECKey) jwk);
                signer.getJCAContext().setProvider(BC_PROVIDER);
                yield signer;
            }
            case ED25519 -> createEd25519Signer((OctetKeyPair) jwk);
        };
    }

    private static JWSSigner createEd25519Signer(OctetKeyPair jwk) {
        byte[] privateKeyBytes = jwk.getD().decode();
        return new JWSSigner() {
            private final JCAContext jcaContext = new JCAContext();

            @Override
            public Base64URL sign(JWSHeader header, byte[] input) throws JOSEException {
                try {
                    var signer = new org.bouncycastle.crypto.signers.Ed25519Signer();
                    signer.init(true, new org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters(privateKeyBytes, 0));
                    signer.update(input, 0, input.length);
                    return Base64URL.encode(signer.generateSignature());
                } catch (Exception e) {
                    throw new JOSEException("Ed25519 signing failed", e);
                }
            }

            @Override
            public Set<JWSAlgorithm> supportedJWSAlgorithms() {
                return Collections.singleton(JWSAlgorithm.EdDSA);
            }

            @Override
            public JCAContext getJCAContext() {
                return jcaContext;
            }
        };
    }
}

