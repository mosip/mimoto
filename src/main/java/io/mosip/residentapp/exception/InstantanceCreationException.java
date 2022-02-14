package io.mosip.residentapp.exception;

/**
 * The Class InstantanceCreationException.
 */
public class InstantanceCreationException extends BaseUncheckedException {

    /** The Constant serialVersionUID. */
    private static final long serialVersionUID = 1L;

    /**
     * Instantiates a new instantance creation exception.
     */
    public InstantanceCreationException() {
        super();
    }

    /**
     * Instantiates a new instantance creation exception.
     *
     * @param errorMessage the error message
     */
    public InstantanceCreationException(String errorMessage) {
        super(PlatformErrorMessages.RESIDENT_APP_SYS_INSTANTIATION_EXCEPTION.getCode() + EMPTY_SPACE, errorMessage);
    }

    /**
     * Instantiates a new instantance creation exception.
     *
     * @param message the message
     * @param cause   the cause
     */
    public InstantanceCreationException(String message, Throwable cause) {
        super(PlatformErrorMessages.RESIDENT_APP_SYS_INSTANTIATION_EXCEPTION.getCode() + EMPTY_SPACE, message, cause);
    }

}
