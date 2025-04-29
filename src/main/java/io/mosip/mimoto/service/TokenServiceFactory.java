package io.mosip.mimoto.service;

import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.OAuth2AuthenticationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class TokenServiceFactory {
    private final Map<String, TokenService> tokenServices;

    @Autowired
    public TokenServiceFactory(Map<String, TokenService> tokenServices) {
        this.tokenServices = tokenServices;
    }

    public TokenService getTokenService(String provider) throws OAuth2AuthenticationException {
        TokenService service = tokenServices.get(provider.toLowerCase());
        if (service == null) {
            throw new OAuth2AuthenticationException(ErrorConstants.INVALID_REQUEST.getErrorCode(), "Unsupported provider: " + provider, HttpStatus.BAD_REQUEST);
        }
        return service;
    }

    public boolean isSupportedProvider(String provider) {
        return tokenServices.containsKey(provider.toLowerCase());
    }
}
