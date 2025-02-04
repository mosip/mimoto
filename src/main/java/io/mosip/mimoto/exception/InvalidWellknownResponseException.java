package io.mosip.mimoto.exception;

public class InvalidWellknownResponseException extends BaseCheckedException {

    public InvalidWellknownResponseException() {
        super(PlatformErrorMessages.INVALID_CREDENTIAL_ISSUER_WELLKNOWN_RESPONSE_EXCEPTION.getCode(), PlatformErrorMessages.INVALID_CREDENTIAL_ISSUER_WELLKNOWN_RESPONSE_EXCEPTION.getMessage());
    }

    public InvalidWellknownResponseException(String message) {
        super(PlatformErrorMessages.INVALID_CREDENTIAL_ISSUER_WELLKNOWN_RESPONSE_EXCEPTION.getCode(), PlatformErrorMessages.INVALID_CREDENTIAL_ISSUER_WELLKNOWN_RESPONSE_EXCEPTION.getMessage() + "\n" + message);

    }

    public InvalidWellknownResponseException(String message, Throwable cause) {
        super(PlatformErrorMessages.INVALID_CREDENTIAL_ISSUER_WELLKNOWN_RESPONSE_EXCEPTION.getCode(), message, cause);
    }

    public InvalidWellknownResponseException(String code, String message) {
        super(code, message);
    }

}
