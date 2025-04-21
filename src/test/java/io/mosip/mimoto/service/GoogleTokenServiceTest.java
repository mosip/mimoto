package io.mosip.mimoto.service;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.mimoto.UserMetadataDTO;
import io.mosip.mimoto.service.impl.GoogleTokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class GoogleTokenServiceTest {

    @Mock
    private JwtDecoder googleIdTokenDecoder;

    @Mock
    private UserMetadataService userMetadataService;

    @Mock
    private SecurityContextService securityContextService;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private HttpSession session;

    @InjectMocks
    private GoogleTokenService googleTokenService;

    @Captor
    private ArgumentCaptor<UserMetadataDTO> userMetadataDTOArgumentCaptor;

    private String idToken;
    private String provider;
    private Jwt validJwt;
    private Map<String, Object> claims;

    @BeforeEach
    void setUp() throws Exception {
        idToken = "dummyIdToken";
        provider = "google";

        // Mock the googleClientId value
        ReflectionTestUtils.setField(googleTokenService, "googleClientId", "google-client-id");

        claims = new HashMap<>();
        claims.put("email", "test@example.com");
        claims.put("name", "Test User");
        claims.put("picture", "http://example.com/picture.jpg");
        claims.put("sub", "google-subject-id");
        claims.put("iss", "https://accounts.google.com");
        claims.put("aud", "google-client-id");
        claims.put("exp", Instant.now().plusSeconds(3600).getEpochSecond());

        validJwt = Jwt.withTokenValue(idToken)
                .header("alg", "RS256")
                .claims(claimsMap -> claimsMap.putAll(claims)) 
                .issuer("https://accounts.google.com")
                .audience(Collections.singletonList("google-client-id"))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();

    }

    @Test
    void processTokenValidTokenShouldCallDependenciesAndSetSessionAndSecurityContext() throws Exception {
        when(googleIdTokenDecoder.decode(idToken)).thenReturn(validJwt);
        when(request.getSession(true)).thenReturn(session);
        when(userMetadataService.updateOrInsertUserMetadata(anyString(), anyString(), anyString(), anyString(), anyString())).thenReturn("test-user-id");

        googleTokenService.processToken(idToken, provider, request, response);

        verify(googleIdTokenDecoder).decode(idToken);
        verify(userMetadataService).updateOrInsertUserMetadata("google-subject-id", provider, "Test User", "http://example.com/picture.jpg", "test@example.com");
        verify(session).setAttribute("clientRegistrationId", provider);
        verify(session).setAttribute(SessionKeys.USER_ID, "test-user-id");
        verify(session).setAttribute(eq(SessionKeys.USER_METADATA), userMetadataDTOArgumentCaptor.capture());

        UserMetadataDTO capturedUserMetadata = userMetadataDTOArgumentCaptor.getValue();
        assertEquals("Test User", capturedUserMetadata.getDisplayName());
        assertEquals("http://example.com/picture.jpg", capturedUserMetadata.getProfilePictureUrl());
        assertEquals("test@example.com", capturedUserMetadata.getEmail());

        verify(securityContextService).setupSecurityContext(any(), eq(request), eq(response));
    }

    @Test
    void processTokenInvalidIssuerShouldThrowException() throws Exception {
        Jwt invalidIssuerJwt = Jwt.withTokenValue(idToken)
                .header("alg", "RS256")
                .claims(claimsMap -> claimsMap.putAll(claims)) 
                .issuer("https://invalid.com")
                .audience(Collections.singletonList("google-client-id"))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();

        when(googleIdTokenDecoder.decode(idToken)).thenReturn(invalidIssuerJwt);

        assertThrows(Exception.class, () -> googleTokenService.processToken(idToken, provider, request, response));

        verify(googleIdTokenDecoder).decode(idToken);
        verifyNoInteractions(userMetadataService, session, securityContextService);
    }

    @Test
    void processTokenInvalidAudienceShouldThrowException() throws Exception {
        Jwt invalidAudienceJwt = Jwt.withTokenValue(idToken)
                .header("alg", "RS256")
                .claims(claimsMap -> claimsMap.putAll(claims)) 
                .issuer("https://accounts.google.com")
                .audience(Collections.singletonList("invalid-client-id"))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();

        when(googleIdTokenDecoder.decode(idToken)).thenReturn(invalidAudienceJwt);

        assertThrows(Exception.class, () -> googleTokenService.processToken(idToken, provider, request, response));

        verify(googleIdTokenDecoder).decode(idToken);
        verifyNoInteractions(userMetadataService, session, securityContextService);
    }

    @Test
    void processTokenMissingEmailClaimShouldThrowException() throws Exception {
        Map<String, Object> claimsWithoutEmail = new HashMap<>(claims);
        claimsWithoutEmail.remove("email");
        Jwt jwtWithoutEmail = Jwt.withTokenValue(idToken)
                .header("alg", "RS256")
                .claims(claimsMap -> claimsMap.putAll(claimsWithoutEmail)) 
                .issuer("https://accounts.google.com")
                .audience(Collections.singletonList("google-client-id"))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();

        when(googleIdTokenDecoder.decode(idToken)).thenReturn(jwtWithoutEmail);

        assertThrows(Exception.class, () -> googleTokenService.processToken(idToken, provider, request, response));

        verify(googleIdTokenDecoder).decode(idToken);
        verifyNoInteractions(userMetadataService, session, securityContextService);
    }

    @Test
    void processTokenEmptyTokenShouldThrowException() {
        assertThrows(Exception.class, () -> googleTokenService.processToken("", provider, request, response));

         verifyNoInteractions(userMetadataService, session, securityContextService);
    }

    @Test
    void processTokenInvalidTokenFormatShouldThrowException() throws Exception {
        when(googleIdTokenDecoder.decode(idToken)).thenThrow(new IllegalArgumentException("Invalid token format"));

        assertThrows(Exception.class, () -> googleTokenService.processToken(idToken, provider, request, response));

        verify(googleIdTokenDecoder).decode(idToken);
        verifyNoInteractions(userMetadataService, session, securityContextService);
    }
}
