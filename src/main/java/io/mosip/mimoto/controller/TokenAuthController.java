package io.mosip.mimoto.controller;

import io.mosip.mimoto.exception.OAuth2AuthenticationException;
import io.mosip.mimoto.service.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class TokenAuthController {

    @Autowired
    private Map<String, TokenService> tokenServices; // Map of provider name to TokenService

    @PostMapping("/auth/{provider}/token-login")
    public ResponseEntity<String> createSessionFromIdToken(@RequestHeader("Authorization") String authorization,
                                                           @PathVariable("provider") String provider,
                                                           HttpServletRequest request, HttpServletResponse response) {
        if (authorization != null && authorization.startsWith("Bearer ")) {
            String idTokenString = authorization.substring(7);
            try {
                TokenService tokenService = tokenServices.get(provider); // Select TokenService by provider
                if (tokenService == null) {
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Unsupported provider: " + provider);
                }
                tokenService.processToken(idTokenString, provider, request, response);
                return ResponseEntity.ok(" Session created.");
            } catch (OAuth2AuthenticationException e) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid or expired ID token: " + e.getMessage());
            }
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Bearer ID token required.");
    }
}