package io.mosip.mimoto.exception;

import java.io.Serial;

public class CredentialNotFoundException extends BaseCheckedException {
    @Serial
    private static final long serialVersionUID = 1L;

    public CredentialNotFoundException(String errorCode, String errorMessage, Throwable cause) {
        super(errorCode, errorMessage, cause);
    }

    public CredentialNotFoundException(String errorCode, String errorMessage) {
        super(errorCode, errorMessage);
    }
}
