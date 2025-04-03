package io.mosip.mimoto.util;

import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.cryptomanager.dto.CryptoWithPinRequestDto;
import io.mosip.kernel.cryptomanager.dto.CryptoWithPinResponseDto;
import io.mosip.kernel.cryptomanager.dto.CryptomanagerRequestDto;
import io.mosip.kernel.cryptomanager.service.CryptomanagerService;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Component
@Slf4j
public class EncryptionDecryptionUtil {
    /**
     * The cryptomanager service.
     */
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

    public String encryptPrivateKeyWithAES(SecretKey aesKey, java.security.PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encryptedPrivateKey = cipher.doFinal(privateKey.getEncoded());
        return Base64.getEncoder().encodeToString(encryptedPrivateKey);
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
