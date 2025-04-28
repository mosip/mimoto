package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.exception.EncryptionException;
import io.mosip.mimoto.exception.DecryptionException;
import io.mosip.mimoto.service.EncryptionService;
import io.mosip.mimoto.util.EncryptionDecryptionUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class EncryptionServiceImpl implements EncryptionService {
    private static final String USER_PII_KEY_REFERENCE_ID = "user_pii";
    private static final String EMPTY_AAD = "";
    private static final String EMPTY_SALT = "";

    private final EncryptionDecryptionUtil encryptionUtil;

    @Autowired
    public EncryptionServiceImpl(EncryptionDecryptionUtil encryptionUtil) {
        this.encryptionUtil = encryptionUtil;
    }

    @Override
    public String encrypt(String data) throws EncryptionException {
        return encryptionUtil.encrypt(data, USER_PII_KEY_REFERENCE_ID, EMPTY_AAD, EMPTY_SALT);
    }

    @Override
    public String decrypt(String data) throws DecryptionException {
        return encryptionUtil.decrypt(data, USER_PII_KEY_REFERENCE_ID, EMPTY_AAD, EMPTY_SALT);
    }
}
