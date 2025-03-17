package io.mosip.mimoto.util;

import io.mosip.kernel.cryptomanager.dto.CryptomanagerRequestDto;
import io.mosip.kernel.cryptomanager.dto.CryptomanagerResponseDto;
import io.mosip.kernel.cryptomanager.service.CryptomanagerService;
import io.mosip.kernel.core.util.CryptoUtil;
import org.apache.commons.lang3.StringUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class EncryptionDecryptionUtilTest {

    @Mock
    private CryptomanagerService cryptomanagerService;

    @InjectMocks
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    private final String refId = "ref123";
    private final String aad = "aad123";
    private final String salt = "salt123";
    private final String encryptedData = "encryptedData";


    @Before
    public void setUp() {
        String appId = "MIMOTO";
        ReflectionTestUtils.setField(encryptionDecryptionUtil, "appId", appId);
    }

    @Test
    public void encrypt_shouldEncryptData() {
        CryptomanagerResponseDto responseDto = new CryptomanagerResponseDto();
        responseDto.setData(encryptedData);
        when(cryptomanagerService.encrypt(any(CryptomanagerRequestDto.class))).thenReturn(responseDto);

        String data = "testData";
        String result = encryptionDecryptionUtil.encrypt(data, refId, aad, salt);

        assertEquals(encryptedData, result);
    }

    @Test
    public void encrypt_shouldReturnNullForBlankData() {
        String result = encryptionDecryptionUtil.encrypt(null, refId, aad, salt);

        assertNull(result);
    }

    @Test
    public void decrypt_shouldDecryptData() {
        CryptomanagerResponseDto responseDto = new CryptomanagerResponseDto();
        String decryptedData = "testData";
        responseDto.setData(CryptoUtil.encodeToURLSafeBase64(decryptedData.getBytes(StandardCharsets.UTF_8)));
        when(cryptomanagerService.decrypt(any(CryptomanagerRequestDto.class))).thenReturn(responseDto);

        String result = encryptionDecryptionUtil.decrypt(encryptedData, refId, aad, salt);

        assertEquals(decryptedData, result);
    }

    @Test
    public void decrypt_shouldReturnNullForBlankData() {
        String result = encryptionDecryptionUtil.decrypt(null, refId, aad, salt);

        assertNull(result);
    }

    @Test
    public void generateEncryptionKey_shouldGenerateKey() throws Exception {
        SecretKey key = EncryptionDecryptionUtil.generateEncryptionKey("AES", 256);

        assertNotNull(key);
        assertEquals("AES", key.getAlgorithm());
    }

    @Test
    public void generateKeyPair_shouldGenerateKeyPair() throws Exception {
        KeyPair keyPair = EncryptionDecryptionUtil.generateKeyPair("Ed25519");

        assertNotNull(keyPair);
        assertEquals("EdDSA", keyPair.getPublic().getAlgorithm());
    }

    @Test
    public void encryptPrivateKeyWithAES_shouldEncryptPrivateKey() throws Exception {
        SecretKey aesKey = EncryptionDecryptionUtil.generateEncryptionKey("AES", 256);
        KeyPair keyPair = EncryptionDecryptionUtil.generateKeyPair("Ed25519");

        String encryptedPrivateKey = EncryptionDecryptionUtil.encryptPrivateKeyWithAES(aesKey, keyPair.getPrivate());

        assertNotNull(encryptedPrivateKey);
        assertFalse(StringUtils.isBlank(encryptedPrivateKey));
    }
}
