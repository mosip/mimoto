package io.mosip.mimoto.exception;

import java.io.Serial;

public class EncryptionException extends BaseUncheckedException {

    @Serial
    private static final long serialVersionUID = 1L;

    public EncryptionException(String errorCode, String errorMessage, Throwable cause) {
        super(errorCode, errorMessage, cause);

    }
}
