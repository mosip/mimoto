package io.mosip.mimoto.util;

import io.mosip.kernel.cryptomanager.service.CryptomanagerService;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import io.mosip.kernel.cryptomanager.dto.CryptomanagerRequestDto;
import io.mosip.kernel.core.util.CryptoUtil;

import java.nio.charset.StandardCharsets;

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
     //   return new String(CryptoUtil.decodeURLSafeBase64(encryptedData));
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

}
