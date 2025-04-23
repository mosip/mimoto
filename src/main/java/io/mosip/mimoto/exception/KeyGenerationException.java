package io.mosip.mimoto.exception;

public class KeyGenerationException extends BaseUncheckedException {

    public KeyGenerationException(String code, String message) {
        super(code, message);
    }

    public KeyGenerationException(String code, String message, Throwable rootCause) {
        super(code, message, rootCause);
    }

} 