package io.mosip.mimoto.exception;

public class CredentialProcessingException extends BaseUncheckedException {
    /** The Constant serialVersionUID. */
    private static final long serialVersionUID = 1L;

    public CredentialProcessingException(String errorCode, String errorMessage, Throwable cause) {
        super(errorCode, errorMessage, cause);

    }

    public CredentialProcessingException(String errorCode, String errorMessage) {
        super(errorCode, errorMessage);

    }
}
