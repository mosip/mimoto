package io.mosip.mimoto.service;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.mimoto.UserMetadataDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.VPNotCreatedException;
import io.mosip.mimoto.service.impl.SessionManager;
import io.mosip.openID4VP.OpenID4VP;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.util.ReflectionTestUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import java.time.Instant;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class SessionManagerTest {

    private SessionManager sessionManager;

    @Mock
    private ObjectMapper objectMapper;

    UserMetadataDTO userMetadataDTO;

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

        assertEquals(provider, session.getAttribute("clientRegistrationId"));
        assertEquals(userMetadataDTO, session.getAttribute(SessionKeys.USER_METADATA));
        assertEquals(userId, session.getAttribute(SessionKeys.USER_ID));
    }

    @Test
    public void shouldCreateAndStorePresentationDetailsInSession() throws Exception {
        Instant fixedInstant = Instant.parse("2025-09-08T12:34:56Z");
        MockHttpSession session = new MockHttpSession();
        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        VerifiablePresentationSessionData presentationSessionData =
                new VerifiablePresentationSessionData(mockOpenID4VP, fixedInstant);
        String expectedPresentationSessionDetails = "{\"createdAt\":\"2025-09-08T12:34:56Z\",\"walletId\":\"wallet123\",\"openID4VPInstance\":{\"mock\":\"json\"}}";
        when(objectMapper.writeValueAsString(any())).thenReturn(expectedPresentationSessionDetails);

        sessionManager.storePresentationSessionDataInSession(session, presentationSessionData, "123e4567-e89b-12d3-a456-426614174000", "wallet123");

        Map<String, String> presentations = (Map<String, String>) session.getAttribute("presentations");

        assertNotNull(presentations);
        assertTrue(presentations.containsKey("123e4567-e89b-12d3-a456-426614174000"));

        String storedPresentationSessionDetails = presentations.get("123e4567-e89b-12d3-a456-426614174000");
        assertNotNull(storedPresentationSessionDetails);
        assertEquals(expectedPresentationSessionDetails, storedPresentationSessionDetails);
    }

    @Test
    public void shouldStorePresentationDetailsProperlyInSessionForMultiplePresentations() throws Exception {
        Instant fixedInstant = Instant.parse("2025-09-08T12:34:56Z");
        MockHttpSession session = new MockHttpSession();

        OpenID4VP mockOpenID4VP1 = mock(OpenID4VP.class);
        OpenID4VP mockOpenID4VP2 = mock(OpenID4VP.class);

        VerifiablePresentationSessionData sessionData1 = new VerifiablePresentationSessionData(mockOpenID4VP1, fixedInstant);
        VerifiablePresentationSessionData sessionData2 = new VerifiablePresentationSessionData(mockOpenID4VP2, fixedInstant);

        // Mock ObjectMapper
        when(objectMapper.writeValueAsString(any())).thenAnswer(invocation -> {
            Object arg = invocation.getArgument(0);
            if (arg == mockOpenID4VP1) return "{\"mock\":\"json1\"}";
            if (arg == mockOpenID4VP2) return "{\"mock\":\"json2\"}";
            if (arg instanceof Map) return new ObjectMapper().writeValueAsString(arg);
            return "{}";
        });

        // Store presentations
        sessionManager.storePresentationSessionDataInSession(session, sessionData1, "123e4567-e89b-12d3-a456-426614174000", "wallet123");
        sessionManager.storePresentationSessionDataInSession(session, sessionData2, "123e4567-e89b-12d3-a456-426614174001", "wallet456");

        Map<String, String> presentations = (Map<String, String>) session.getAttribute("presentations");
        assertNotNull(presentations);

        // Expected JSON strings
        String expectedSessionPresentationData1 = "{\"createdAt\":\"2025-09-08T12:34:56Z\",\"walletId\":\"wallet123\",\"openID4VPInstance\":\"{\\\"mock\\\":\\\"json1\\\"}\"}",
                expectedSessionPresentationData2 = "{\"createdAt\":\"2025-09-08T12:34:56Z\",\"walletId\":\"wallet456\",\"openID4VPInstance\":\"{\\\"mock\\\":\\\"json2\\\"}\"}";

        // Compare directly as strings
        assertEquals(expectedSessionPresentationData1, presentations.get("123e4567-e89b-12d3-a456-426614174000"));
        assertEquals(expectedSessionPresentationData2, presentations.get("123e4567-e89b-12d3-a456-426614174001"));
    }

    @Test
    public void shouldThrowErrorOnSerializationFailureWhenStoringPresentationDetailsInSession() throws Exception {
        Instant fixedInstant = Instant.parse("2025-09-08T12:34:56Z");
        MockHttpSession session = new MockHttpSession();
        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(mockOpenID4VP, fixedInstant);

        when(objectMapper.writeValueAsString(eq(mockOpenID4VP)))
                .thenThrow(new JsonParseException("Error occurred while serializing OpenID4VP"));

        try {
            sessionManager.storePresentationSessionDataInSession(session, sessionData,
                    "123e4567-e89b-12d3-a456-426614174000", "wallet123");
            fail("Expected VPNotCreatedException to be thrown");
        } catch (VPNotCreatedException e) {
            String expectedErrorMessage = "Failed to serialize presentation data - Error occurred while serializing OpenID4VP";
            assertEquals("invalid_request", e.getErrorCode());
            assertEquals(expectedErrorMessage, e.getErrorText());
        }
    }
}
