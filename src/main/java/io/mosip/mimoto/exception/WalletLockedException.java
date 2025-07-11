package io.mosip.mimoto.exception;

import java.io.Serial;

public class WalletLockedException extends BaseUncheckedException {

    @Serial
    private static final long serialVersionUID = 1L;

    public WalletLockedException(String errorCode, String errorMessage) {
        super(errorCode, errorMessage);
    }
}
