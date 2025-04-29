package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.mimoto.UserMetadataDTO;
import io.mosip.mimoto.exception.DecryptionException;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.exception.OAuth2AuthenticationException;
import io.mosip.mimoto.service.SecurityContextService;
import io.mosip.mimoto.service.TokenDecoder;
import io.mosip.mimoto.service.TokenService;
import io.mosip.mimoto.service.UserMetadataService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static io.mosip.mimoto.exception.ErrorConstants.INVALID_REQUEST;
import static io.mosip.mimoto.exception.ErrorConstants.OAUTH2_AUTHENTICATION_EXCEPTION;

@Service("google")
@Slf4j
public class GoogleTokenService implements TokenService {
    private static final String MISSING_EMAIL_ERROR = "Missing email in ID token";
    private static final String INVALID_ISSUER_ERROR = "Invalid issuer";
    private static final String INVALID_AUDIENCE_ERROR = "Invalid audience";
    private static final String TOKEN_EXPIRED_ERROR = "Token expired";

    private final TokenDecoder tokenDecoder;
    private final UserMetadataService userMetadataService;
    private final SecurityContextManager securityContextManager;
    private final SessionManager sessionManager;
    private final String expectedIssuer;
    private final String expectedAudience;

    @Autowired
    public GoogleTokenService(
            @Qualifier("googleJwtDecoder") TokenDecoder tokenDecoder,
            UserMetadataService userMetadataService,
            SecurityContextManager securityContextManager,
            SessionManager sessionManager,
            @Value("${spring.security.oauth2.client.registration.google.client-id}") String clientId,
            @Value("${google.issuer:https://accounts.google.com}") String issuer) {
        this.tokenDecoder = tokenDecoder;
        this.userMetadataService = userMetadataService;
        this.securityContextManager = securityContextManager;
        this.sessionManager = sessionManager;
        this.expectedAudience = clientId;
        this.expectedIssuer = issuer;
    }

    @Override
    public void processToken(String idToken, String provider, HttpServletRequest request, HttpServletResponse response)
            throws OAuth2AuthenticationException {
        Jwt jwt = validateToken(idToken);
        String email = extractClaim(jwt, "email");
        if (email == null) {
            log.error(MISSING_EMAIL_ERROR);
            throw new OAuth2AuthenticationException("missing_email", MISSING_EMAIL_ERROR, HttpStatus.UNAUTHORIZED);
        }

        String name = extractClaim(jwt, "name");
        String picture = extractClaim(jwt, "picture");
        String sub = extractClaim(jwt, "sub");

        String userId = null;
        try {
            userId = userMetadataService.updateOrInsertUserMetadata(sub, provider, name, picture, email);
        } catch (DecryptionException e) {
            log.error("Failed to store the user info in the database", e);
            throw new RuntimeException();
        }
        sessionManager.setupSession(request, provider, new UserMetadataDTO(name, picture, email), userId);
        securityContextManager.setupSecurityContext(createOAuth2Token(provider, sub, name, picture, email), request, response);
    }

    private Jwt validateToken(String idToken) throws OAuth2AuthenticationException {
        Jwt jwt = tokenDecoder.decode(idToken);
        if (!expectedIssuer.equals(jwt.getIssuer().toString())) {
            log.error("Invalid issuer: {}", jwt.getIssuer());
            throw new OAuth2AuthenticationException("invalid_issuer", INVALID_ISSUER_ERROR, HttpStatus.UNAUTHORIZED);
        }
        if (!expectedAudience.equals(jwt.getAudience().stream().findFirst().orElse(null))) {
            log.error("Invalid audience: {}", jwt.getAudience());
            throw new OAuth2AuthenticationException("invalid_audience", INVALID_AUDIENCE_ERROR, HttpStatus.UNAUTHORIZED);
        }
        if (jwt.getExpiresAt() == null || jwt.getExpiresAt().isBefore(Instant.now())) {
            log.error("Token expired");
            throw new OAuth2AuthenticationException("token_expired", TOKEN_EXPIRED_ERROR, HttpStatus.UNAUTHORIZED);
        }
        return jwt;
    }

    private String extractClaim(Jwt jwt, String claimName) {
        return (String) jwt.getClaims().get(claimName);
    }

    private OAuth2AuthenticationToken createOAuth2Token(String provider, String sub, String name, String picture, String email) {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("sub", sub);
        attributes.put("name", name);
        attributes.put("picture", picture);
        attributes.put("email", email);

        List<GrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
        OAuth2User oAuth2User = new DefaultOAuth2User(authorities, attributes, "sub");
        return new OAuth2AuthenticationToken(oAuth2User, authorities, provider);
    }
}
