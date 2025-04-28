package io.mosip.mimoto.exception;

/**
 * Exception thrown when a user attempts to access a wallet or credential that doesn't belong to them
 */
public class UnauthorizedWalletAccessException extends BaseUncheckedException {

    private static final long serialVersionUID = 1L;

    /**
     * Instantiates a new unauthorized wallet access exception.
     */
    public UnauthorizedWalletAccessException() {
        super(PlatformErrorMessages.MIMOTO_AUT_ACCESS_DENIED.getCode(), "Unauthorized access to wallet or credential");
    }

    /**
     * Instantiates a new unauthorized wallet access exception with a specific message.
     *
     * @param message the error message
     */
    public UnauthorizedWalletAccessException(String message) {
        super(PlatformErrorMessages.MIMOTO_AUT_ACCESS_DENIED.getCode(), message);
    }

    /**
     * Instantiates a new unauthorized wallet access exception with a message and cause.
     *
     * @param message the error message
     * @param cause   the cause
     */
    public UnauthorizedWalletAccessException(String message, Throwable cause) {
        super(PlatformErrorMessages.MIMOTO_AUT_ACCESS_DENIED.getCode(), message, cause);
    }
}
