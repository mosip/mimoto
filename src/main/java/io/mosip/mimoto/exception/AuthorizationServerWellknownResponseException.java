package io.mosip.mimoto.exception;

public class AuthorizationServerWellknownResponseException extends BaseCheckedException {
    public AuthorizationServerWellknownResponseException(String message) {
        super(PlatformErrorMessages.INVALID_AUTHORIZATION_SERVER_WELLKNOWN_RESPONSE_EXCEPTION.getCode(), PlatformErrorMessages.INVALID_AUTHORIZATION_SERVER_WELLKNOWN_RESPONSE_EXCEPTION.getMessage() + "\n" + message);
    }
}
