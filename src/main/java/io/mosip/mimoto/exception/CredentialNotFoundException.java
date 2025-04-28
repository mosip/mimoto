package io.mosip.mimoto.exception;

/**
 * Exception thrown when a credential is not found
 */
public class CredentialNotFoundException extends BaseUncheckedException {

    private static final long serialVersionUID = 1L;

    /**
     * Instantiates a new credential not found exception.
     */
    public CredentialNotFoundException() {
        super(PlatformErrorMessages.CREDENTIAL_DELETE_EXCEPTION.getCode(), "Credential not found");
    }

    /**
     * Instantiates a new credential not found exception with a specific message.
     *
     * @param message the error message
     */
    public CredentialNotFoundException(String message) {
        super(PlatformErrorMessages.CREDENTIAL_DELETE_EXCEPTION.getCode(), message);
    }

    /**
     * Instantiates a new credential not found exception with a message and cause.
     *
     * @param message the error message
     * @param cause   the cause
     */
    public CredentialNotFoundException(String message, Throwable cause) {
        super(PlatformErrorMessages.CREDENTIAL_DELETE_EXCEPTION.getCode(), message, cause);
    }
}
