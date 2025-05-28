package io.mosip.mimoto.exception;

import java.io.Serial;

public class UnAuthorizationAccessException extends BaseUncheckedException {

    @Serial
    private static final long serialVersionUID = 1L;

    public UnAuthorizationAccessException(String errorCode, String errorMessage) {
        super(errorCode, errorMessage);
    }
}
