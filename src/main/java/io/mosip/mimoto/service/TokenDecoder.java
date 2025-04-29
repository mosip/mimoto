package io.mosip.mimoto.service;

import io.mosip.mimoto.exception.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.Jwt;

public interface TokenDecoder {
    Jwt decode(String idToken) throws OAuth2AuthenticationException;
}
