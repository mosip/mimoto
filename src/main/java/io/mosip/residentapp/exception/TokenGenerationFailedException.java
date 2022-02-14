package io.mosip.residentapp.exception;

public class TokenGenerationFailedException extends BaseUncheckedException {

    /** The Constant serialVersionUID. */
    private static final long serialVersionUID = 1L;

    /**
     * Instantiates a new ABIS abort exception.
     */
    public TokenGenerationFailedException() {
        super();
    }

    /**
     * Instantiates a new ABIS abort exception.
     *
     * @param errorMessage
     *                     the error message
     */
    public TokenGenerationFailedException(String errorMessage) {
        super(PlatformErrorMessages.RESIDENT_APP_BDD_ABIS_ABORT.getCode() + EMPTY_SPACE, errorMessage);
    }

    /**
     * Instantiates a new ABIS abort exception.
     *
     * @param message
     *                the message
     * @param cause
     *                the cause
     */
    public TokenGenerationFailedException(String message, Throwable cause) {
        super(PlatformErrorMessages.RESIDENT_APP_BDD_ABIS_ABORT.getCode() + EMPTY_SPACE, message, cause);
    }
}
