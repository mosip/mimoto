package io.mosip.mimoto.exception;

public class DecryptionException extends BaseCheckedException {

    /**
     *
     */
    private static final long serialVersionUID = 1L;


    public DecryptionException(String errorCode, String errorMessage) {
        super(errorCode, errorMessage);

    }

    public DecryptionException(String errorCode, String errorMessage, Throwable cause) {
        super(errorCode, errorMessage, cause);

    }
}
