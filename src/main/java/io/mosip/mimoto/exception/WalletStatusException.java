package io.mosip.mimoto.exception;

import java.io.Serial;

public class WalletStatusException extends BaseUncheckedException {

    @Serial
    private static final long serialVersionUID = 1L;

    public WalletStatusException(String errorCode, String errorMessage) {
        super(errorCode, errorMessage);
    }
}
