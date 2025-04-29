package io.mosip.mimoto.exception;

public class CredentialPdfGenerationException extends BaseUncheckedException {
    /** The Constant serialVersionUID. */
    private static final long serialVersionUID = 1L;

    public CredentialPdfGenerationException() {
        super();
    }

    public CredentialPdfGenerationException(String errorCode, String errorMessage) {
        super(errorCode, errorMessage);

    }

    public CredentialPdfGenerationException(String errorCode, String errorMessage, Throwable cause) {
        super(errorCode, errorMessage, cause);

    }
}
