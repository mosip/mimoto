package io.mosip.mimoto.exception;

public class PushedAuthorizationRequestException extends RuntimeException {

    public PushedAuthorizationRequestException(String message) {
        super(message);
    }

    public PushedAuthorizationRequestException(String message, Throwable cause) {
        super(message, cause);
    }
}
