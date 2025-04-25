package io.mosip.mimoto.exception;

public class ExternalServiceUnavailableException extends BaseCheckedException {
    /** The Constant serialVersionUID. */
    private static final long serialVersionUID = 1L;

    public ExternalServiceUnavailableException() {
        super();
    }

    public ExternalServiceUnavailableException(String errorCode, String errorMessage) {
        super(errorCode, errorMessage);

    }

    public ExternalServiceUnavailableException(String errorCode, String errorMessage, Throwable cause) {
        super(errorCode, errorMessage, cause);

    }
}
