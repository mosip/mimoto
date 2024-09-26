package io.mosip.mimoto.exception;

public class InvalidVerifierException extends BaseUncheckedException {

    private static final long serialVersionUID = -5350213197226295789L;

    /**
     * Constructor with errorCode, and errorMessage
     *
     * @param errorCode    The error code for this exception
     * @param errorMessage The error message for this exception
     */
    public InvalidVerifierException(String errorCode, String errorMessage) {
        super(errorCode, errorMessage);
    }

    public InvalidVerifierException(String errorMessage) {
        super(PlatformErrorMessages.MIMOTO_PGS_INVALID_INPUT_PARAMETER.getCode(), errorMessage);
    }
}
