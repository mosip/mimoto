package io.mosip.mimoto.exception;

import java.io.Serial;

public class WalletUnlockEligibilityException extends BaseUncheckedException {

    @Serial
    private static final long serialVersionUID = 1L;

    public WalletUnlockEligibilityException(String errorCode, String errorMessage) {
        super(errorCode, errorMessage);
    }
}
