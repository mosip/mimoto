package io.mosip.residentapp.exception;

public class InvalidTokenException extends BaseUncheckedException {

    /** The Constant serialVersionUID. */
    private static final long serialVersionUID = 1L;

    /**
     * Instantiates a new timeout exception.
     */
    public InvalidTokenException() {
        super();

    }

    /**
     * Instantiates a new timeout exception.
     *
     * @param code    the exceptionCode
     * @param message the message
     */
    public InvalidTokenException(String code, String message) {
        super(code, message);
    }

    /**
     * Instantiates a new timeout exception.
     *
     * @param message the message
     */
    public InvalidTokenException(String message) {
        super(PlatformErrorMessages.RESIDENT_APP_AUT_INVALID_TOKEN.getCode(), message);
    }

    /**
     * Instantiates a new timeout exception.
     *
     * @param message the message
     * @param cause   the cause
     */
    public InvalidTokenException(String message, Throwable cause) {
        super(PlatformErrorMessages.RESIDENT_APP_AUT_INVALID_TOKEN.getCode() + EMPTY_SPACE, message, cause);
    }
}
