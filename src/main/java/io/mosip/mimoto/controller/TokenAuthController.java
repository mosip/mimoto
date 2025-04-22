package io.mosip.mimoto.controller;

import io.mosip.mimoto.constant.SwaggerLiteralConstants;
import io.mosip.mimoto.exception.OAuth2AuthenticationException;
import io.mosip.mimoto.service.TokenService;
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

    @Autowired
    private Map<String, TokenService> tokenServices; // Map of provider name to TokenService

    @Operation(summary = "Login and create session using OAuth2 ID token", description = "This API accepts an OAuth2 ID token in the Authorization header and establishes a session by populating Spring Security context.\n\nFetch the ID token from a supported OAuth2 provider (such as Google or Microsoft) and provide it in the request as a Bearer token.", operationId = "loginWithOAuth2IdToken", security = @SecurityRequirement(name = "bearerAuth"), parameters = {@Parameter(name = "provider", in = ParameterIn.PATH, required = true, description = "The OAuth2 provider to use for login. Example values: 'google', 'microsoft', 'facebook'.", schema = @Schema(type = "string", example = "google")), @Parameter(name = "Authorization", in = ParameterIn.HEADER, required = true, description = "The OAuth2 ID token that must be provided in the 'Authorization' header, prefixed with 'Bearer '.", schema = @Schema(type = "string", example = "Bearer <id-token>"))})
    @ApiResponse(responseCode = "200", description = "Successfully logged in and session created", content = @Content(mediaType = "application/json", schema = @Schema(type = "string", description = "Success message indicating that the session has been created"), examples = @ExampleObject(value = "\"Session created.\"")))
    @ApiResponse(responseCode = "401", description = "Unauthorized - invalid or expired token", content = @Content(mediaType = "application/json", schema = @Schema(type = "string", description = "Error message explaining why the session is not created"), examples = {@ExampleObject(value = "\"Invalid or expired ID token: please provide a valid token\""), @ExampleObject(value = "\"Bearer ID token required\"")}))
    @ApiResponse(responseCode = "400", description = "Bad Request - Unsupported provider", content = @Content(mediaType = "application/json", schema = @Schema(type = "string", description = "Error message explaining why the session is not created"), examples = @ExampleObject(value = "\"Unsupported provider: provider123\"")))
    @PostMapping("/auth/{provider}/token-login")
    public ResponseEntity<String> createSessionFromIdToken(@RequestHeader("Authorization") String authorization, @PathVariable("provider") String provider, HttpServletRequest request, HttpServletResponse response) {
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