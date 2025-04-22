package io.mosip.mimoto.util;

import io.mosip.mimoto.model.SigningAlgorithm;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class KeyGenerationUtilTest {

    @Test
    public void shouldGenerateEncryptionKeySuccessfully() throws Exception {
        SecretKey key = KeyGenerationUtil.generateEncryptionKey("AES", 256);

        assertNotNull(key);
        assertEquals("AES", key.getAlgorithm());
    }

    @Test
    public void shouldGenerateKeyPairSuccessfully() throws Exception {
        KeyPair keyPair = KeyGenerationUtil.generateKeyPair(SigningAlgorithm.ED25519);

        assertNotNull(keyPair);
        assertEquals("EdDSA", keyPair.getPublic().getAlgorithm());
    }

    @Test
    public void shouldGenerateRSAKeyPairSuccessfully() throws Exception {
        KeyPair keyPair = KeyGenerationUtil.generateKeyPair(SigningAlgorithm.RS256);

        assertNotNull(keyPair);
        assertEquals("RSA", keyPair.getPublic().getAlgorithm());
    }

    @Test
    public void shouldGenerateECKeyPairWithP256Successfully() throws Exception {
        KeyPair keyPair = KeyGenerationUtil.generateKeyPair(SigningAlgorithm.ES256);

        assertNotNull(keyPair);
        assertEquals("EC", keyPair.getPublic().getAlgorithm());
    }

    @Test
    public void shouldGenerateECKeyPairWithSecp256k1Successfully() throws Exception {
        KeyPair keyPair = KeyGenerationUtil.generateKeyPair(SigningAlgorithm.ES256K);

        assertNotNull(keyPair);
        assertEquals("EC", keyPair.getPublic().getAlgorithm());
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowExceptionForUnsupportedAlgorithm() throws Exception {
        KeyGenerationUtil.generateKeyPair(SigningAlgorithm.fromString("unsupportedAlgorithm"));
    }

    @Test(expected = NoSuchAlgorithmException.class)
    public void shouldThrowExceptionForUnsupportedEncryptionAlgorithm() throws Exception {
        KeyGenerationUtil.generateEncryptionKey("unsupportedAlgorithm", 256);
    }
}
