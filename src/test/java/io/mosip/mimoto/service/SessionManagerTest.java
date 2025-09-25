package io.mosip.mimoto.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.mimoto.UserMetadataDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.dto.MatchingCredentialsResponseDTO;
import io.mosip.mimoto.dto.DecryptedCredentialDTO;
import io.mosip.mimoto.model.CredentialMetadata;
import io.mosip.mimoto.service.impl.SessionManager;
import io.mosip.openID4VP.OpenID4VP;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.*;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class SessionManagerTest {

    UserMetadataDTO userMetadataDTO;
    private SessionManager sessionManager;
    @Mock
    private ObjectMapper objectMapper;

    @Before
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        sessionManager = new SessionManager();
        ReflectionTestUtils.setField(sessionManager, "objectMapper", objectMapper);
        userMetadataDTO = new UserMetadataDTO("Test user", "https://test.com/pic.jpg", "test@example.com", "wallet123");
    }

    @Test
    public void shouldSetupSessionWithProvidedUserAndOAuth2ProviderDetails() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpSession session = new MockHttpSession();
        when(request.getSession(true)).thenReturn(session);

        String provider = "google";
        String userId = "123";

        sessionManager.setupSession(request, provider, userMetadataDTO, userId);

        assertEquals(provider, session.getAttribute(SessionKeys.CLIENT_REGISTRATION_ID));
        assertEquals(userMetadataDTO, session.getAttribute(SessionKeys.USER_METADATA));
        assertEquals(userId, session.getAttribute(SessionKeys.USER_ID));
    }

    @Test
    public void shouldCreateAndStorePresentationDetailsInSession() {
        Instant fixedInstant = Instant.parse("2025-09-08T12:34:56Z");
        MockHttpSession session = new MockHttpSession();
        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        String walletId = "wallet123";
        String presentationId = "123e4567-e89b-12d3-a456-426614174000";
        VerifiablePresentationSessionData presentationSessionData = new VerifiablePresentationSessionData(presentationId, "authorizationRequest", fixedInstant, false,  null);

        sessionManager.storePresentationSessionData(session, presentationSessionData, walletId);

        Map<String, VerifiablePresentationSessionData> presentations =
                (Map<String, VerifiablePresentationSessionData>) session.getAttribute(SessionKeys.PRESENTATIONS + "::" + walletId);

        assertNotNull(presentations);
        assertTrue(presentations.containsKey(presentationId));

        VerifiablePresentationSessionData storedPresentationSessionDetails = presentations.get(presentationId);
        assertNotNull(storedPresentationSessionDetails);
        assertEquals(presentationSessionData.getAuthorizationRequest(), storedPresentationSessionDetails.getAuthorizationRequest());
        assertEquals(presentationSessionData.getCreatedAt(), storedPresentationSessionDetails.getCreatedAt());
    }

    @Test
    public void shouldStorePresentationDetailsProperlyInSessionForMultiplePresentations() {
        Instant fixedInstant = Instant.parse("2025-09-08T12:34:56Z");
        MockHttpSession session = new MockHttpSession();

        OpenID4VP mockOpenID4VP1 = mock(OpenID4VP.class);
        OpenID4VP mockOpenID4VP2 = mock(OpenID4VP.class);

        String walletId1 = "wallet123";
        String walletId2 = "wallet456";
        String presentationId1 = "123e4567-e89b-12d3-a456-426614174000";
        String presentationId2 = "123e4567-e89b-12d3-a456-426614174001";

        VerifiablePresentationSessionData sessionData1 = new VerifiablePresentationSessionData(presentationId1, "authorizationRequest", fixedInstant, true, null);
        VerifiablePresentationSessionData sessionData2 = new VerifiablePresentationSessionData(presentationId2, "authorizationRequest", fixedInstant, false, null);

        sessionManager.storePresentationSessionData(session, sessionData1, walletId1);
        sessionManager.storePresentationSessionData(session, sessionData2, walletId2);

        Map<String, VerifiablePresentationSessionData> presentations1 =
                (Map<String, VerifiablePresentationSessionData>) session.getAttribute(SessionKeys.PRESENTATIONS + "::" + walletId1);
        Map<String, VerifiablePresentationSessionData> presentations2 =
                (Map<String, VerifiablePresentationSessionData>) session.getAttribute(SessionKeys.PRESENTATIONS + "::" + walletId2);

        assertNotNull(presentations1);
        assertNotNull(presentations2);

        assertTrue(presentations1.containsKey(presentationId1));
        assertTrue(presentations2.containsKey(presentationId2));

        VerifiablePresentationSessionData storedData1 = presentations1.get(presentationId1);
        VerifiablePresentationSessionData storedData2 = presentations2.get(presentationId2);

        assertNotNull(storedData1);
        assertNotNull(storedData2);

        assertEquals(sessionData1.getAuthorizationRequest(), storedData1.getAuthorizationRequest());
        assertEquals(sessionData1.getCreatedAt(), storedData1.getCreatedAt());
        assertEquals(sessionData2.getAuthorizationRequest(), storedData2.getAuthorizationRequest());
        assertEquals(sessionData2.getCreatedAt(), storedData2.getCreatedAt());
    }

    @Test
    public void shouldReturnPresentationDefinitionFromSessionSuccessfully() {
        Instant fixedInstant = Instant.parse("2025-09-08T12:34:56Z");
        String presentationId = "test-presentation-id";
        String walletId = "wallet123";
        MockHttpSession session = new MockHttpSession();

        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(presentationId,"mockOpenID4VP", fixedInstant,  true, null);

        Map<String, VerifiablePresentationSessionData> presentations = new HashMap<>();
        presentations.put(presentationId, sessionData);
        session.setAttribute(SessionKeys.PRESENTATIONS + "::" + walletId, presentations);

        VerifiablePresentationSessionData result = sessionManager.getPresentationSessionData(session, walletId, presentationId);

        assertNotNull(result);
        assertNotNull(result.getAuthorizationRequest());
        assertEquals(fixedInstant, result.getCreatedAt());
    }

    @Test
    public void shouldReturnNullWhenNoPresentationsInSession() {
        String presentationId = "test-presentation-id";
        String walletId = "wallet123";
        MockHttpSession session = new MockHttpSession();

        VerifiablePresentationSessionData result = sessionManager.getPresentationSessionData(session, walletId, presentationId);

        assertNull(result);
    }

    @Test
    public void shouldReturnNullWhenPresentationIdNotFound() {
        String presentationId = "non-existent-id";
        String walletId = "wallet123";
        MockHttpSession session = new MockHttpSession();

        Map<String, VerifiablePresentationSessionData> presentations = new HashMap<>();
        session.setAttribute(SessionKeys.PRESENTATIONS + "::" + walletId, presentations);

        VerifiablePresentationSessionData result = sessionManager.getPresentationSessionData(session, walletId, presentationId);

        assertNull(result);
    }
}
