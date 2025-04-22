package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.mimoto.UserMetadataDTO;
import io.mosip.mimoto.exception.OAuth2AuthenticationException;
import io.mosip.mimoto.service.SecurityContextService;
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
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static io.mosip.mimoto.exception.PlatformErrorMessages.OAUTH2_AUTHENTICATION_EXCEPTION;

@Service("google")
@Slf4j
public class GoogleTokenService implements TokenService {

    @Autowired
    @Qualifier("googleJwtDecoder")
    private JwtDecoder googleIdTokenDecoder;

    @Autowired
    private UserMetadataService userMetadataService;

    @Autowired
    private SecurityContextService securityContextService;

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String googleClientId;

    @Override
    public void processToken(String idToken, String provider, HttpServletRequest request, HttpServletResponse response) throws OAuth2AuthenticationException {
        Jwt jwt = decodeAndValidateToken(idToken);

        String email = extractClaim(jwt, "email");
        String name = extractClaim(jwt, "name");
        String picture = extractClaim(jwt, "picture");
        String sub = extractClaim(jwt, "sub");

        if (email != null) {
            String userId = userMetadataService.updateOrInsertUserMetadata(sub, provider, name, picture, email);
            setupSession(request, provider, name, picture, email, userId);
            setupSecurityContext(provider, sub, name, picture, email, request, response);
        } else {
            log.error("Could not extract user information from ID token ");
            throw new OAuth2AuthenticationException(OAUTH2_AUTHENTICATION_EXCEPTION.getCode(),OAUTH2_AUTHENTICATION_EXCEPTION.getMessage(), HttpStatus.UNAUTHORIZED);
        }
    }

    private Jwt decodeAndValidateToken(String idToken) throws OAuth2AuthenticationException {
        Jwt jwt = googleIdTokenDecoder.decode(idToken);

        String issuer = jwt.getIssuer().toString();
        if (!issuer.equals("https://accounts.google.com") && !issuer.equals("accounts.google.com")) {
            log.error("Invalid ID token issuer: " + issuer);
            throw new OAuth2AuthenticationException(OAUTH2_AUTHENTICATION_EXCEPTION.getCode(),OAUTH2_AUTHENTICATION_EXCEPTION.getMessage(), HttpStatus.UNAUTHORIZED);
        }

        String audience = jwt.getAudience().stream().findFirst().orElse(null);
        if (!googleClientId.equals(audience)) {
            log.error("Invalid ID token audience: " + audience);
            throw new OAuth2AuthenticationException(OAUTH2_AUTHENTICATION_EXCEPTION.getCode(),OAUTH2_AUTHENTICATION_EXCEPTION.getMessage(), HttpStatus.UNAUTHORIZED);
        }

        return jwt;
    }

    private String extractClaim(Jwt jwt, String claimName) {
        return (String) jwt.getClaims().get(claimName);
    }

    private void setupSession(HttpServletRequest request, String provider, String name, String picture, String email, String userId) {
        HttpSession session = request.getSession(true);
        UserMetadataDTO userMetadataDTO = new UserMetadataDTO(name, picture, email);
        session.setAttribute("clientRegistrationId", provider);
        session.setAttribute(SessionKeys.USER_METADATA, userMetadataDTO);
        session.setAttribute(SessionKeys.USER_ID, userId);
    }

    private void setupSecurityContext(String provider, String sub, String name, String picture, String email, HttpServletRequest request, HttpServletResponse response) {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("sub", sub);
        attributes.put("name", name);
        attributes.put("picture", picture);
        attributes.put("email", email);

        List<GrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
        OAuth2User oAuth2User = new DefaultOAuth2User(authorities, attributes, "sub");
        OAuth2AuthenticationToken oauth2AuthenticationToken = new OAuth2AuthenticationToken(oAuth2User, authorities, provider);

        securityContextService.setupSecurityContext(oauth2AuthenticationToken, request, response);
    }
}
