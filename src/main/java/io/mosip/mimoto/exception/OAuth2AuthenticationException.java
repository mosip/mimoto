package io.mosip.mimoto.exception;

import org.springframework.http.HttpStatus;

public class OAuth2AuthenticationException extends BaseCheckedException {
    private final HttpStatus status;
    
    public OAuth2AuthenticationException(String code, String message, HttpStatus status) {
        super(code, message);
        this.status=status;
    }

    public HttpStatus getStatus() {
        return status;
    }
}

