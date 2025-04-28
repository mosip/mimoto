package io.mosip.mimoto.exception;

import java.io.Serial;

public class InvalidRequestException extends BaseUncheckedException {

    @Serial
    private static final long serialVersionUID = 1L;

    public InvalidRequestException(String errorCode, String errorMessage, Throwable cause) {
        super(errorCode, errorMessage, cause);
    }

    public InvalidRequestException(String errorCode, String errorMessage) {
        super(errorCode, errorMessage);
    }
}
