package io.mosip.mimoto.service;

import io.mosip.mimoto.exception.EncryptionException;
import io.mosip.mimoto.exception.DecryptionException;

public interface EncryptionService {
    String encrypt(String data) throws EncryptionException;
    String decrypt(String data) throws DecryptionException;
}
