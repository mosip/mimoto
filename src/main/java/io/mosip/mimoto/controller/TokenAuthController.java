package io.mosip.mimoto.controller;

import io.mosip.mimoto.constant.SwaggerLiteralConstants;
import io.mosip.mimoto.exception.OAuth2AuthenticationException;
import io.mosip.mimoto.service.TokenService;
import io.mosip.mimoto.service.TokenServiceFactory;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;

import java.util.Map;

@RestController
@Tag(name = SwaggerLiteralConstants.ID_TOKEN_AUTHENTICATION_NAME, description = SwaggerLiteralConstants.ID_TOKEN_AUTHENTICATION_DESCRIPTION)
public class TokenAuthController {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final String SESSION_CREATED = "Session created.";
    private static final String INVALID_TOKEN_MESSAGE = "Bearer ID token required.";
    private static final String UNSUPPORTED_PROVIDER_MESSAGE = "Unsupported provider: %s";
    private static final String INVALID_TOKEN_ERROR = "Invalid or expired ID token: %s";

    private final TokenServiceFactory tokenServiceFactory;

    @Autowired
    public TokenAuthController(TokenServiceFactory tokenServiceFactory) {
        this.tokenServiceFactory = tokenServiceFactory;
    }

    @Operation(summary = "Login and create session using OAuth2 ID token", description = "This API accepts an OAuth2 ID token in the Authorization header and establishes a session by populating Spring Security context.\n\nFetch the ID token from a supported OAuth2 provider (such as Google or Microsoft) and provide it in the request as a Bearer token.", operationId = "loginWithOAuth2IdToken", security = @SecurityRequirement(name = "bearerAuth"), parameters = {@Parameter(name = "provider", in = ParameterIn.PATH, required = true, description = "The OAuth2 provider to use for login. Example values: 'google', 'microsoft', 'facebook'.", schema = @Schema(type = "string", example = "google")), @Parameter(name = "Authorization", in = ParameterIn.HEADER, required = true, description = "The OAuth2 ID token that must be provided in the 'Authorization' header, prefixed with 'Bearer '.", schema = @Schema(type = "string", example = "Bearer <id-token>"))})
    @ApiResponse(responseCode = "200", description = "Successfully logged in and session created", content = @Content(mediaType = "application/json", schema = @Schema(type = "string", description = "Success message indicating that the session has been created"), examples = @ExampleObject(value = "\"Session created.\"")))
    @ApiResponse(responseCode = "401", description = "Unauthorized - invalid or expired token", content = @Content(mediaType = "application/json", schema = @Schema(type = "string", description = "Error message explaining why the session is not created"), examples = {@ExampleObject(value = "\"Invalid or expired ID token: please provide a valid token\""), @ExampleObject(value = "\"Bearer ID token required\"")}))
    @ApiResponse(responseCode = "400", description = "Bad Request - Unsupported provider", content = @Content(mediaType = "application/json", schema = @Schema(type = "string", description = "Error message explaining why the session is not created"), examples = @ExampleObject(value = "\"Unsupported provider: provider123\"")))
    @PostMapping("/auth/{provider}/token-login")
    public ResponseEntity<String> createSessionFromIdToken(@RequestHeader("Authorization") String authorization, @PathVariable("provider") String provider, HttpServletRequest request, HttpServletResponse response) {
        if (!tokenServiceFactory.isSupportedProvider(provider)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(String.format(UNSUPPORTED_PROVIDER_MESSAGE, provider));
        }
        if (authorization == null || !authorization.startsWith(BEARER_PREFIX)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(INVALID_TOKEN_MESSAGE);
        }

        String idToken = authorization.substring(BEARER_PREFIX.length());
        try {
            TokenService tokenService = tokenServiceFactory.getTokenService(provider);
            tokenService.processToken(idToken, provider, request, response);
            return ResponseEntity.ok(SESSION_CREATED);
        } catch (OAuth2AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(String.format(INVALID_TOKEN_ERROR, e.getMessage()));
        }
    }
}