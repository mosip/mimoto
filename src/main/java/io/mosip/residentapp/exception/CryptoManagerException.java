package io.mosip.residentapp.exception;

import io.mosip.kernel.core.exception.BaseUncheckedException;

public class CryptoManagerException extends BaseUncheckedException {

    /** The Constant serialVersionUID. */
    private static final long serialVersionUID = 1L;

    /**
     * Instantiates a new access denied exception.
     */
    public CryptoManagerException() {
        super();

    }

    /**
     * Instantiates a new access denied exception.
     *
     * @param message the message
     */
    public CryptoManagerException(String message) {
        super(PlatformErrorMessages.RESIDENT_APP_AUT_ACCESS_DENIED.getCode(), message);
    }

    public CryptoManagerException(String message, String message1) {
        super(PlatformErrorMessages.RESIDENT_APP_AUT_ACCESS_DENIED.getCode(), message);
    }

    /**
     * Instantiates a new access denied exception.
     *
     * @param message the message
     * @param cause   the cause
     */
    public CryptoManagerException(String message, String message1, Throwable cause) {
        super(PlatformErrorMessages.RESIDENT_APP_AUT_ACCESS_DENIED.getCode(), message, cause);
    }
}
