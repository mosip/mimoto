package io.mosip.residentapp.exception;

public class AccessDeniedException extends BaseUncheckedException {

    /** The Constant serialVersionUID. */
    private static final long serialVersionUID = 1L;

    /**
     * Instantiates a new access denied exception.
     */
    public AccessDeniedException() {
        super();

    }

    /**
     * Instantiates a new access denied exception.
     *
     * @param message the message
     */
    public AccessDeniedException(String message) {
        super(PlatformErrorMessages.RESIDENT_APP_AUT_ACCESS_DENIED.getCode(), message);
    }

    /**
     * Instantiates a new access denied exception.
     *
     * @param message the message
     * @param cause   the cause
     */
    public AccessDeniedException(String message, Throwable cause) {
        super(PlatformErrorMessages.RESIDENT_APP_AUT_ACCESS_DENIED.getCode(), message, cause);
    }
}
