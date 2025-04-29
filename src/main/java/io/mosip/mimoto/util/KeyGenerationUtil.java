package io.mosip.mimoto.util;

import io.mosip.mimoto.exception.KeyGenerationException;
import io.mosip.mimoto.model.SigningAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import static io.mosip.mimoto.exception.ErrorConstants.ENCRYPTION_FAILED;

public class KeyGenerationUtil {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * Generates a key pair for the given algorithm.
     *
     * @param algorithm The algorithm to use (e.g., "RS256", "ES256", "ES256K", "Ed25519").
     * @return KeyPair object.
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchProviderException
     */
    public static KeyPair generateKeyPair(SigningAlgorithm algorithm) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = null;

        switch (algorithm) {
            case RS256:
                keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(2048);
                break;
            case ES256:
                keyPairGenerator = KeyPairGenerator.getInstance("EC");
                ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
                keyPairGenerator.initialize(ecGenParameterSpec);
                break;
            case ES256K:
                keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
                ECGenParameterSpec ecGenParameterSpecK = new ECGenParameterSpec("secp256k1");
                keyPairGenerator.initialize(ecGenParameterSpecK);
                break;
            case ED25519:
                keyPairGenerator = KeyPairGenerator.getInstance("Ed25519");
                break;
        }

        if (keyPairGenerator == null) {
            throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }

        return keyPairGenerator.generateKeyPair();
    }


    public static KeyPair getKeyPairFromDBStoredKeys(SigningAlgorithm algorithm, byte[] publicKeyBytes, byte[] privateKeyBytes) throws Exception {
        KeyFactory keyFactory = switch (algorithm) {
            case ES256K -> KeyFactory.getInstance(algorithm.getKeyFactoryAlgorithm(), "BC");
            default -> KeyFactory.getInstance(algorithm.getKeyFactoryAlgorithm());
        };

        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

        return new KeyPair(publicKey, privateKey);
    }


    /**
     * Generates a secret key for the given algorithm and key size.
     *
     * @param algorithm The algorithm to use (e.g., "AES").
     * @param keysize   The key size in bits.
     * @return SecretKey object.
     */
    public static SecretKey generateEncryptionKey(String algorithm, int keysize)  {
        KeyGenerator keyGenerator = null;
        try {
            keyGenerator = KeyGenerator.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyGenerationException(ENCRYPTION_FAILED.getErrorCode(), ENCRYPTION_FAILED.getErrorMessage(), e);
        }
        keyGenerator.init(keysize);
        return keyGenerator.generateKey();
    }
}