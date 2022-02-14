package io.mosip.residentapp.exception;

/**
 * The Class ParsingException.
 */
public class ParsingException extends BaseUncheckedException {

    /** The Constant serialVersionUID. */
    private static final long serialVersionUID = 1L;

    /**
     * Instantiates a new parsing exception.
     */
    public ParsingException() {
        super();
    }

    /**
     * Instantiates a new parsing exception.
     *
     * @param errorMessage the error message
     */
    public ParsingException(String errorMessage) {
        super(PlatformErrorMessages.RESIDENT_APP_RGS_JSON_PARSING_EXCEPTION.getCode() + EMPTY_SPACE, errorMessage);
    }

    /**
     * Instantiates a new parsing exception.
     *
     * @param message the message
     * @param cause   the cause
     */
    public ParsingException(String message, Throwable cause) {
        super(PlatformErrorMessages.RESIDENT_APP_RGS_JSON_PARSING_EXCEPTION.getCode() + EMPTY_SPACE, message, cause);
    }

}
