
package io.mosip.mimoto.exception;

import org.springframework.http.HttpStatus;

public class LoginSessionException extends BaseCheckedException {
    private final HttpStatus status;

    public LoginSessionException(String code, String message, HttpStatus status) {
        super(code, message);
        this.status = status;
    }

    public HttpStatus getStatus() {
        return status;
    }
}
