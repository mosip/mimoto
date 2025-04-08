package io.mosip.mimoto.util;

import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.cryptomanager.dto.CryptoWithPinRequestDto;
import io.mosip.kernel.cryptomanager.dto.CryptoWithPinResponseDto;
import io.mosip.kernel.cryptomanager.dto.CryptomanagerRequestDto;
import io.mosip.kernel.cryptomanager.service.CryptomanagerService;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

@Component
public class EncryptionDecryptionUtil {
    /**
     * The cryptomanager service.
     */

    private static final int GCM_IV_LENGTH = 12;   // 12-byte IV for GCM
    private static final int GCM_TAG_LENGTH = 128; // 128-bit authentication tag

    @Autowired
    private CryptomanagerService cryptomanagerService;
    private
    @Value("${spring.application.name}")
    String appId;

    public String encrypt(String dataToEncrypt, String refId, String aad, String saltToEncrypt) {
        if (StringUtils.isBlank(dataToEncrypt)) {
            return null;
        }
        CryptomanagerRequestDto request = new CryptomanagerRequestDto();
        request.setApplicationId(appId.toUpperCase());
        request.setTimeStamp(DateUtils.getUTCCurrentDateTime());
        request.setData(CryptoUtil.encodeToURLSafeBase64(dataToEncrypt.getBytes(StandardCharsets.UTF_8)));
        request.setReferenceId(refId);
        request.setAad(aad);
        request.setSalt(saltToEncrypt);
        return cryptomanagerService.encrypt(request).getData();
    }

    public String decrypt(String dataToDecrypt, String refId, String aad, String saltToDecrypt) {
        if (StringUtils.isBlank(dataToDecrypt)) {
            return null;
        }
        CryptomanagerRequestDto request = new CryptomanagerRequestDto();
        request.setApplicationId(appId.toUpperCase());
        request.setTimeStamp(DateUtils.getUTCCurrentDateTime());
        request.setData(dataToDecrypt);
        request.setReferenceId(refId);
        request.setAad(aad);
        request.setSalt(saltToDecrypt);
        return new String(CryptoUtil.decodeURLSafeBase64(cryptomanagerService.decrypt(request).getData()));
    }

     /**
     * Encrypts the given data using AES-GCM.
     *
     * @param aesKey The AES secret key
     * @param data   The data to encrypt (as byte[])
     * @return Base64 encoded string of (IV + encryptedData)
     */
    public String encryptWithAES(SecretKey aesKey, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        // Generate a secure random IV
        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);

        // Initialize cipher with AES key & IV
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);

        // Encrypt the data
        byte[] encryptedData = cipher.doFinal(data);

        // Combine IV + Encrypted Data
        byte[] finalEncryptedData = new byte[GCM_IV_LENGTH + encryptedData.length];
        System.arraycopy(iv, 0, finalEncryptedData, 0, GCM_IV_LENGTH);
        System.arraycopy(encryptedData, 0, finalEncryptedData, GCM_IV_LENGTH, encryptedData.length);

        return Base64.getEncoder().encodeToString(finalEncryptedData);
    }

    /**
     * Decrypts the given Base64 encoded data using AES-GCM.
     *
     * @param aesKey        The AES secret key
     * @param base64EncodedData Base64 encoded string of (IV + encryptedData)
     * @return Decrypted data as byte[]
     */
    public byte[] decryptWithAES(SecretKey aesKey, String base64EncodedData) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] decodedData = Base64.getDecoder().decode(base64EncodedData);

        // Extract IV and Encrypted Data
        byte[] iv = new byte[GCM_IV_LENGTH];
        byte[] encryptedData = new byte[decodedData.length - GCM_IV_LENGTH];

        System.arraycopy(decodedData, 0, iv, 0, GCM_IV_LENGTH);
        System.arraycopy(decodedData, GCM_IV_LENGTH, encryptedData, 0, encryptedData.length);

        // Initialize cipher with AES key & extracted IV
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);

        return cipher.doFinal(encryptedData);
    }

    public static byte[] stringToBytes(String data) {
        return data.getBytes(StandardCharsets.UTF_8);
    }

    public static String bytesToString(byte[] data) {
        return new String(data, StandardCharsets.UTF_8);
    }

    public static SecretKey bytesToSecretKey(byte[] keyBytes) {
        return new javax.crypto.spec.SecretKeySpec(keyBytes, "AES");
    }
    public static PrivateKey bytesToPrivateKey(byte[] privateKeyBytes, String algorithmName) throws Exception {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithmName);
        return keyFactory.generatePrivate(keySpec);
    }
    
    public String decryptWithPin(String encryptedString, String pin) {
        CryptoWithPinRequestDto requestDto = new CryptoWithPinRequestDto();
        requestDto.setUserPin(pin);
        requestDto.setData(encryptedString);
        CryptoWithPinResponseDto responseDto = cryptomanagerService.decryptWithPin(requestDto);
        return responseDto.getData();
    }

    public String encryptKeyWithPin(SecretKey encryptionKey, String pin) {
        CryptoWithPinRequestDto requestDto = new CryptoWithPinRequestDto();
        requestDto.setUserPin(pin);
        String dataAsString = Base64.getEncoder().encodeToString(encryptionKey.getEncoded());
        requestDto.setData(dataAsString);
        return cryptomanagerService.encryptWithPin(requestDto).getData();
    }
}