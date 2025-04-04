package io.mosip.mimoto.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

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
    public static KeyPair generateKeyPair(String algorithm) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator;

        switch (algorithm) {
            case "RS256":
                keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(2048);
                break;
            case "ES256":
                keyPairGenerator = KeyPairGenerator.getInstance("EC");
                ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256r1");
                keyPairGenerator.initialize(ecGenParameterSpec);
                break;
            case "ES256K":
                keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
                ECGenParameterSpec ecGenParameterSpecK = new ECGenParameterSpec("secp256k1");
                keyPairGenerator.initialize(ecGenParameterSpecK);
                break;
            case "Ed25519":
                keyPairGenerator = KeyPairGenerator.getInstance("Ed25519");
                break;
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }

        return keyPairGenerator.generateKeyPair();
    }


    /**
     * Generates a secret key for the given algorithm and key size.
     *
     * @param algorithm The algorithm to use (e.g., "AES").
     * @param keysize   The key size in bits.
     * @return SecretKey object.
     * @throws NoSuchAlgorithmException
     */
    public static SecretKey generateEncryptionKey(String algorithm, int keysize) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
        keyGenerator.init(keysize);
        return keyGenerator.generateKey();
    }


}