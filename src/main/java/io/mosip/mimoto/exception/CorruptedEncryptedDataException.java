package io.mosip.mimoto.exception;

public class CorruptedEncryptedDataException extends BaseCheckedException {
    private static final long serialVersionUID = 1L;


    public CorruptedEncryptedDataException(String errorCode, String errorMessage) {
        super(errorCode, errorMessage);

    }

    public CorruptedEncryptedDataException(String errorCode, String errorMessage, Throwable cause) {
        super(errorCode, errorMessage, cause);

    }
}
