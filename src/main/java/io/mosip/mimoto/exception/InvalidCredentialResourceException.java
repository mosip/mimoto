package io.mosip.mimoto.exception;

public class InvalidCredentialResourceException extends BaseUncheckedException {

    private static final long serialVersionUID = -5350213197226295789L;

    /**
     * Constructor with errorCode, and errorMessage
     *
     * @param errorCode    The error code for this exception
     * @param errorMessage The error message for this exception
     */
    public InvalidCredentialResourceException(String errorCode, String errorMessage) {
        super(errorCode, errorMessage);
    }

    public InvalidCredentialResourceException(String errorMessage) {
        super(OpenIdErrorMessages.RESOURCE_NOT_FOUND.getErrorCode(), errorMessage);
    }
}
