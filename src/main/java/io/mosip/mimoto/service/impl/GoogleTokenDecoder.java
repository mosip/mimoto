package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.exception.OAuth2AuthenticationException;
import io.mosip.mimoto.service.TokenDecoder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;

@Component
@Qualifier("googleJwtDecoder")
public class GoogleTokenDecoder implements TokenDecoder {
    private final JwtDecoder jwtDecoder;

    @Autowired
    public GoogleTokenDecoder(@Qualifier("googleJwtDecoder") JwtDecoder jwtDecoder) {
        this.jwtDecoder = jwtDecoder;
    }

    @Override
    public Jwt decode(String idToken) throws OAuth2AuthenticationException {
        try {
            return jwtDecoder.decode(idToken);
        } catch (JwtException e) {
            throw new InvalidRequestException("invalid_token", e.getMessage(), e);
        }
    }
}