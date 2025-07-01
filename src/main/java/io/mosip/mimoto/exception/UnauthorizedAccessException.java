package io.mosip.mimoto.exception;

import java.io.Serial;

public class UnauthorizedAccessException extends BaseUncheckedException {

    @Serial
    private static final long serialVersionUID = 1L;

    public UnauthorizedAccessException(String errorCode, String errorMessage) {
        super(errorCode, errorMessage);
    }
}
