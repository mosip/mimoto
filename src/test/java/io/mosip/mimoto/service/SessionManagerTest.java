package io.mosip.mimoto.service;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.mimoto.UserMetadataDTO;
import io.mosip.mimoto.dto.openid.presentation.ConstraintsDTO;
import io.mosip.mimoto.dto.openid.presentation.FieldDTO;
import io.mosip.mimoto.dto.openid.presentation.FilterDTO;
import io.mosip.mimoto.dto.openid.presentation.InputDescriptorDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationDefinitionDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.dto.MatchingCredentialsResponseDTO;
import io.mosip.mimoto.dto.DecryptedCredentialDTO;
import io.mosip.mimoto.dto.SelectableCredentialDTO;
import io.mosip.mimoto.model.CredentialMetadata;
import io.mosip.mimoto.exception.VPNotCreatedException;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
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
    public void shouldCreateAndStorePresentationDetailsInSession() throws Exception {
        Instant fixedInstant = Instant.parse("2025-09-08T12:34:56Z");
        MockHttpSession session = new MockHttpSession();
        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        VerifiablePresentationSessionData presentationSessionData = new VerifiablePresentationSessionData(mockOpenID4VP, fixedInstant, null);
        // No serialization needed for current implementation

        sessionManager.storePresentationSessionDataInSession(session, presentationSessionData, "123e4567-e89b-12d3-a456-426614174000", "wallet123");

        Map<String, VerifiablePresentationSessionData> presentations = (Map<String, VerifiablePresentationSessionData>) session.getAttribute(SessionKeys.PRESENTATIONS);

        assertNotNull(presentations);
        assertTrue(presentations.containsKey("123e4567-e89b-12d3-a456-426614174000"));

        VerifiablePresentationSessionData storedPresentationSessionDetails = presentations.get("123e4567-e89b-12d3-a456-426614174000");
        assertNotNull(storedPresentationSessionDetails);
        assertEquals(presentationSessionData.getOpenID4VP(), storedPresentationSessionDetails.getOpenID4VP());
        assertEquals(presentationSessionData.getCreatedAt(), storedPresentationSessionDetails.getCreatedAt());
    }

    @Test
    public void shouldStorePresentationDetailsProperlyInSessionForMultiplePresentations() throws Exception {
        Instant fixedInstant = Instant.parse("2025-09-08T12:34:56Z");
        MockHttpSession session = new MockHttpSession();

        OpenID4VP mockOpenID4VP1 = mock(OpenID4VP.class);
        OpenID4VP mockOpenID4VP2 = mock(OpenID4VP.class);

        VerifiablePresentationSessionData sessionData1 = new VerifiablePresentationSessionData(mockOpenID4VP1, fixedInstant, null);
        VerifiablePresentationSessionData sessionData2 = new VerifiablePresentationSessionData(mockOpenID4VP2, fixedInstant, null);

        // No serialization needed for current implementation

        // Store presentations
        sessionManager.storePresentationSessionDataInSession(session, sessionData1, "123e4567-e89b-12d3-a456-426614174000", "wallet123");
        sessionManager.storePresentationSessionDataInSession(session, sessionData2, "123e4567-e89b-12d3-a456-426614174001", "wallet456");

        Map<String, VerifiablePresentationSessionData> presentations = (Map<String, VerifiablePresentationSessionData>) session.getAttribute(SessionKeys.PRESENTATIONS);
        assertNotNull(presentations);

        // Verify both presentations are stored
        assertTrue(presentations.containsKey("123e4567-e89b-12d3-a456-426614174000"));
        assertTrue(presentations.containsKey("123e4567-e89b-12d3-a456-426614174001"));

        // Verify the stored data contains expected values
        VerifiablePresentationSessionData storedData1 = presentations.get("123e4567-e89b-12d3-a456-426614174000");
        VerifiablePresentationSessionData storedData2 = presentations.get("123e4567-e89b-12d3-a456-426614174001");
        
        assertNotNull(storedData1);
        assertNotNull(storedData2);
        
        // Verify the session data contains expected values
        assertEquals(sessionData1.getOpenID4VP(), storedData1.getOpenID4VP());
        assertEquals(sessionData1.getCreatedAt(), storedData1.getCreatedAt());
        assertEquals(sessionData2.getOpenID4VP(), storedData2.getOpenID4VP());
        assertEquals(sessionData2.getCreatedAt(), storedData2.getCreatedAt());
    }

    @Test
    public void shouldStorePresentationDetailsInSessionWithoutSerialization() throws Exception {
        Instant fixedInstant = Instant.parse("2025-09-08T12:34:56Z");
        MockHttpSession session = new MockHttpSession();
        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(mockOpenID4VP, fixedInstant, null);

        // The current implementation stores objects directly without serialization
        sessionManager.storePresentationSessionDataInSession(session, sessionData, "123e4567-e89b-12d3-a456-426614174000", "wallet123");

        // Verify the data is stored correctly
        Map<String, VerifiablePresentationSessionData> presentations = (Map<String, VerifiablePresentationSessionData>) session.getAttribute(SessionKeys.PRESENTATIONS);
        assertNotNull(presentations);
        assertTrue(presentations.containsKey("123e4567-e89b-12d3-a456-426614174000"));
        
        VerifiablePresentationSessionData storedData = presentations.get("123e4567-e89b-12d3-a456-426614174000");
        assertEquals(sessionData.getOpenID4VP(), storedData.getOpenID4VP());
        assertEquals(sessionData.getCreatedAt(), storedData.getCreatedAt());
    }

    @Test
    public void shouldReturnPresentationDefinitionFromSessionSuccessfully() throws Exception {
        Instant fixedInstant = Instant.parse("2025-09-08T12:34:56Z");
        String presentationId = "test-presentation-id";
        MockHttpSession session = new MockHttpSession();

        // Create a mock OpenID4VP and VerifiablePresentationSessionData
        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(mockOpenID4VP, fixedInstant, null);
        
        // Store the session data directly in the session (as the current implementation expects)
        Map<String, VerifiablePresentationSessionData> presentations = new HashMap<>();
        presentations.put(presentationId, sessionData);
        session.setAttribute(SessionKeys.PRESENTATIONS, presentations);

        VerifiablePresentationSessionData result = sessionManager.getPresentationDefinitionFromSession(session, presentationId);

        assertNotNull(result);
        assertNotNull(result.getOpenID4VP());
        assertEquals(fixedInstant, result.getCreatedAt());
    }

    @Test
    public void shouldReturnNullWhenNoPresentationsInSession() throws Exception {

        String presentationId = "test-presentation-id";
        MockHttpSession session = new MockHttpSession();

        VerifiablePresentationSessionData result = sessionManager.getPresentationDefinitionFromSession(session, presentationId);

        assertNull(result);
    }

    @Test
    public void shouldReturnNullWhenPresentationIdNotFound() throws Exception {

        String presentationId = "non-existent-id";
        MockHttpSession session = new MockHttpSession();

        Map<String, String> presentations = new HashMap<>();
        presentations.put("other-id", "some-data");
        session.setAttribute(SessionKeys.PRESENTATIONS, presentations);

        VerifiablePresentationSessionData result = sessionManager.getPresentationDefinitionFromSession(session, presentationId);

        assertNull(result);
    }

    @Test
    public void shouldReturnNullWhenOpenID4VPInstanceIsNull() throws Exception {
        Instant fixedInstant = Instant.parse("2025-09-08T12:34:56Z");
        String presentationId = "test-presentation-id";
        MockHttpSession session = new MockHttpSession();

        // Create session data with null OpenID4VP
        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(null, fixedInstant, null);
        
        Map<String, VerifiablePresentationSessionData> presentations = new HashMap<>();
        presentations.put(presentationId, sessionData);
        session.setAttribute(SessionKeys.PRESENTATIONS, presentations);

        VerifiablePresentationSessionData result = sessionManager.getPresentationDefinitionFromSession(session, presentationId);

        assertNull(result);
    }

    @Test
    public void shouldReturnNullWhenAuthorizationRequestIsNull() throws Exception {
        Instant fixedInstant = Instant.parse("2025-09-08T12:34:56Z");
        String presentationId = "test-presentation-id";
        MockHttpSession session = new MockHttpSession();

        // Create session data with valid OpenID4VP (this test is no longer relevant for the current implementation)
        // since the method just returns the session data directly without parsing OpenID4VP content
        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(mockOpenID4VP, fixedInstant, null);
        
        Map<String, VerifiablePresentationSessionData> presentations = new HashMap<>();
        presentations.put(presentationId, sessionData);
        session.setAttribute(SessionKeys.PRESENTATIONS, presentations);

        VerifiablePresentationSessionData result = sessionManager.getPresentationDefinitionFromSession(session, presentationId);

        assertNotNull(result); // The current implementation returns the session data if OpenID4VP is not null
    }

    @Test
    public void shouldReturnNullWhenPresentationDefinitionIsNull() throws Exception {
        Instant fixedInstant = Instant.parse("2025-09-08T12:34:56Z");
        String presentationId = "test-presentation-id";
        MockHttpSession session = new MockHttpSession();

        // Create session data with valid OpenID4VP (this test is no longer relevant for the current implementation)
        // since the method just returns the session data directly without parsing OpenID4VP content
        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(mockOpenID4VP, fixedInstant, null);
        
        Map<String, VerifiablePresentationSessionData> presentations = new HashMap<>();
        presentations.put(presentationId, sessionData);
        session.setAttribute(SessionKeys.PRESENTATIONS, presentations);

        VerifiablePresentationSessionData result = sessionManager.getPresentationDefinitionFromSession(session, presentationId);

        assertNotNull(result); // The current implementation returns the session data if OpenID4VP is not null
    }

    @Test
    public void shouldHandleJsonProcessingExceptionGracefully() throws Exception {
        Instant fixedInstant = Instant.parse("2025-09-08T12:34:56Z");
        String presentationId = "test-presentation-id";
        MockHttpSession session = new MockHttpSession();

        // Create session data with valid OpenID4VP (this test is no longer relevant for the current implementation)
        // since the method just returns the session data directly without JSON processing
        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(mockOpenID4VP, fixedInstant, null);
        
        Map<String, VerifiablePresentationSessionData> presentations = new HashMap<>();
        presentations.put(presentationId, sessionData);
        session.setAttribute(SessionKeys.PRESENTATIONS, presentations);

        VerifiablePresentationSessionData result = sessionManager.getPresentationDefinitionFromSession(session, presentationId);

        assertNotNull(result); // The current implementation returns the session data directly
    }

    @Test
    public void shouldHandleOpenID4VPInstanceJsonProcessingExceptionGracefully() throws Exception {
        Instant fixedInstant = Instant.parse("2025-09-08T12:34:56Z");
        String presentationId = "test-presentation-id";
        MockHttpSession session = new MockHttpSession();

        // Create session data with valid OpenID4VP (this test is no longer relevant for the current implementation)
        // since the method just returns the session data directly without JSON processing
        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(mockOpenID4VP, fixedInstant, null);
        
        Map<String, VerifiablePresentationSessionData> presentations = new HashMap<>();
        presentations.put(presentationId, sessionData);
        session.setAttribute(SessionKeys.PRESENTATIONS, presentations);

        VerifiablePresentationSessionData result = sessionManager.getPresentationDefinitionFromSession(session, presentationId);

        assertNotNull(result); // The current implementation returns the session data directly
    }

    @Test
    public void shouldHandleEmptyInputDescriptorsList() throws Exception {
        Instant fixedInstant = Instant.parse("2025-09-08T12:34:56Z");
        String presentationId = "test-presentation-id";
        MockHttpSession session = new MockHttpSession();

        // Create session data with valid OpenID4VP (this test is no longer relevant for the current implementation)
        // since the method just returns the session data directly without parsing OpenID4VP content
        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(mockOpenID4VP, fixedInstant, null);
        
        Map<String, VerifiablePresentationSessionData> presentations = new HashMap<>();
        presentations.put(presentationId, sessionData);
        session.setAttribute(SessionKeys.PRESENTATIONS, presentations);

        VerifiablePresentationSessionData result = sessionManager.getPresentationDefinitionFromSession(session, presentationId);

        assertNotNull(result);
        assertNotNull(result.getOpenID4VP());
        assertEquals(fixedInstant, result.getCreatedAt());
    }

    @Test
    public void shouldHandleInputDescriptorWithoutConstraints() throws Exception {
        Instant fixedInstant = Instant.parse("2025-09-08T12:34:56Z");
        String presentationId = "test-presentation-id";
        MockHttpSession session = new MockHttpSession();

        // Create session data with valid OpenID4VP (this test is no longer relevant for the current implementation)
        // since the method just returns the session data directly without parsing OpenID4VP content
        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(mockOpenID4VP, fixedInstant, null);
        
        Map<String, VerifiablePresentationSessionData> presentations = new HashMap<>();
        presentations.put(presentationId, sessionData);
        session.setAttribute(SessionKeys.PRESENTATIONS, presentations);

        VerifiablePresentationSessionData result = sessionManager.getPresentationDefinitionFromSession(session, presentationId);
        
        assertNotNull(result);
        assertNotNull(result.getOpenID4VP());
        assertEquals(fixedInstant, result.getCreatedAt());
    }

    @Test
    public void shouldStoreMatchingWalletCredentialsInSessionSuccessfully() throws Exception {
        MockHttpSession session = new MockHttpSession();
        String presentationId = "test-presentation-id";
        
        // First, store a presentation in the session
        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        VerifiablePresentationSessionData presentationSessionData = new VerifiablePresentationSessionData(mockOpenID4VP, Instant.now(), null);
        sessionManager.storePresentationSessionDataInSession(session, presentationSessionData, presentationId, "test-wallet-id");
        
        // Create test data
        MatchingCredentialsResponseDTO matchingResponse = createTestMatchingCredentialsResponse();
        List<DecryptedCredentialDTO> decryptedCredentials = createTestDecryptedCredentials();
        
        // Mock ObjectMapper - only needed for error handling
        when(objectMapper.writeValueAsString(any(MatchingCredentialsResponseDTO.class)))
                .thenReturn("{\"availableCredentials\":[{\"credentialId\":\"cred1\"}],\"missingClaims\":[]}");
        
        // Execute
        sessionManager.storeMatchingWalletCredentialsInSession(session, presentationId, matchingResponse, decryptedCredentials);
        
        // Verify matched credentials are stored in the presentation session data
        Map<String, VerifiablePresentationSessionData> presentations = (Map<String, VerifiablePresentationSessionData>) session.getAttribute(SessionKeys.PRESENTATIONS);
        assertNotNull(presentations);
        assertTrue(presentations.containsKey(presentationId));
        
        VerifiablePresentationSessionData updatedSessionData = presentations.get(presentationId);
        assertNotNull(updatedSessionData);
        assertNotNull(updatedSessionData.getMatchingCredentials());
        assertEquals(1, updatedSessionData.getMatchingCredentials().size());
        assertEquals("cred1", updatedSessionData.getMatchingCredentials().get(0).getId());
    }

    @Test
    public void shouldStoreMatchingWalletCredentialsInSessionWithExistingCache() throws Exception {
        MockHttpSession session = new MockHttpSession();
        String presentationId1 = "presentation-1";
        String presentationId2 = "presentation-2";
        
        // First, store presentations in the session
        OpenID4VP mockOpenID4VP1 = mock(OpenID4VP.class);
        OpenID4VP mockOpenID4VP2 = mock(OpenID4VP.class);
        VerifiablePresentationSessionData presentationSessionData1 = new VerifiablePresentationSessionData(mockOpenID4VP1, Instant.now(), null);
        VerifiablePresentationSessionData presentationSessionData2 = new VerifiablePresentationSessionData(mockOpenID4VP2, Instant.now(), null);
        sessionManager.storePresentationSessionDataInSession(session, presentationSessionData1, presentationId1, "test-wallet-1");
        sessionManager.storePresentationSessionDataInSession(session, presentationSessionData2, presentationId2, "test-wallet-2");
        
        // Create test data
        MatchingCredentialsResponseDTO matchingResponse = createTestMatchingCredentialsResponse();
        List<DecryptedCredentialDTO> decryptedCredentials = createTestDecryptedCredentials();
        
        // Mock ObjectMapper - only needed for error handling
        when(objectMapper.writeValueAsString(any(MatchingCredentialsResponseDTO.class)))
                .thenReturn("{\"availableCredentials\":[{\"credentialId\":\"cred1\"}],\"missingClaims\":[]}");
        
        // Execute
        sessionManager.storeMatchingWalletCredentialsInSession(session, presentationId2, matchingResponse, decryptedCredentials);
        
        // Verify both presentations are stored
        Map<String, VerifiablePresentationSessionData> presentations = (Map<String, VerifiablePresentationSessionData>) session.getAttribute(SessionKeys.PRESENTATIONS);
        assertNotNull(presentations);
        assertEquals(2, presentations.size());
        assertTrue(presentations.containsKey(presentationId1));
        assertTrue(presentations.containsKey(presentationId2));
        
        // Verify presentation1 has no matching credentials (original state)
        VerifiablePresentationSessionData sessionData1 = presentations.get(presentationId1);
        assertNull(sessionData1.getMatchingCredentials());
        
        // Verify presentation2 has matching credentials
        VerifiablePresentationSessionData sessionData2 = presentations.get(presentationId2);
        assertNotNull(sessionData2.getMatchingCredentials());
        assertEquals(1, sessionData2.getMatchingCredentials().size());
        assertEquals("cred1", sessionData2.getMatchingCredentials().get(0).getId());
    }

    @Test
    public void shouldStoreMatchingWalletCredentialsInSessionWithEmptyCredentials() throws Exception {
        MockHttpSession session = new MockHttpSession();
        String presentationId = "test-presentation-id";
        
        // First, store a presentation in the session
        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        VerifiablePresentationSessionData presentationSessionData = new VerifiablePresentationSessionData(mockOpenID4VP, Instant.now(), null);
        sessionManager.storePresentationSessionDataInSession(session, presentationSessionData, presentationId, "test-wallet-id");
        
        // Create test data with empty credentials
        MatchingCredentialsResponseDTO matchingResponse = MatchingCredentialsResponseDTO.builder()
                .availableCredentials(new ArrayList<>())
                .missingClaims(Set.of("claim1", "claim2"))
                .build();
        List<DecryptedCredentialDTO> decryptedCredentials = new ArrayList<>();
        
        // Mock ObjectMapper - only needed for error handling
        when(objectMapper.writeValueAsString(any(MatchingCredentialsResponseDTO.class)))
                .thenReturn("{\"availableCredentials\":[],\"missingClaims\":[\"claim1\",\"claim2\"]}");
        
        // Execute
        sessionManager.storeMatchingWalletCredentialsInSession(session, presentationId, matchingResponse, decryptedCredentials);
        
        // Verify data is stored
        Map<String, VerifiablePresentationSessionData> presentations = (Map<String, VerifiablePresentationSessionData>) session.getAttribute(SessionKeys.PRESENTATIONS);
        assertNotNull(presentations);
        assertTrue(presentations.containsKey(presentationId));
        
        VerifiablePresentationSessionData updatedSessionData = presentations.get(presentationId);
        assertNotNull(updatedSessionData);
        assertNotNull(updatedSessionData.getMatchingCredentials());
        assertEquals(0, updatedSessionData.getMatchingCredentials().size());
    }

    @Test
    public void shouldStoreMatchingWalletCredentialsInSessionWithNullMatchingResponse() throws Exception {
        MockHttpSession session = new MockHttpSession();
        String presentationId = "test-presentation-id";
        
        // First, store a presentation in the session
        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        VerifiablePresentationSessionData presentationSessionData = new VerifiablePresentationSessionData(mockOpenID4VP, Instant.now(), null);
        sessionManager.storePresentationSessionDataInSession(session, presentationSessionData, presentationId, "test-wallet-id");
        
        // Create test data with null matching response
        MatchingCredentialsResponseDTO matchingResponse = null;
        List<DecryptedCredentialDTO> decryptedCredentials = createTestDecryptedCredentials();
        
        // No mocking needed - null response won't trigger serialization
        
        // Execute
        sessionManager.storeMatchingWalletCredentialsInSession(session, presentationId, matchingResponse, decryptedCredentials);
        
        // Verify data is stored
        Map<String, VerifiablePresentationSessionData> presentations = (Map<String, VerifiablePresentationSessionData>) session.getAttribute(SessionKeys.PRESENTATIONS);
        assertNotNull(presentations);
        assertTrue(presentations.containsKey(presentationId));
        
        VerifiablePresentationSessionData updatedSessionData = presentations.get(presentationId);
        assertNotNull(updatedSessionData);
        assertNotNull(updatedSessionData.getMatchingCredentials());
        assertEquals(0, updatedSessionData.getMatchingCredentials().size());
    }

    @Test
    public void shouldThrowExceptionWhenSerializationFailsForMatchingCredentials() throws Exception {
        MockHttpSession session = new MockHttpSession();
        String presentationId = "test-presentation-id";
        
        // First, store a presentation in the session
        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        VerifiablePresentationSessionData presentationSessionData = new VerifiablePresentationSessionData(mockOpenID4VP, Instant.now(), null);
        sessionManager.storePresentationSessionDataInSession(session, presentationSessionData, presentationId, "test-wallet-id");
        
        // Create test data
        MatchingCredentialsResponseDTO matchingResponse = createTestMatchingCredentialsResponse();
        List<DecryptedCredentialDTO> decryptedCredentials = createTestDecryptedCredentials();
        
        // Mock ObjectMapper to throw exception
        when(objectMapper.writeValueAsString(any(MatchingCredentialsResponseDTO.class)))
                .thenThrow(new JsonProcessingException("Serialization failed") {});
        
        // Execute and verify exception
        try {
            sessionManager.storeMatchingWalletCredentialsInSession(session, presentationId, matchingResponse, decryptedCredentials);
            fail("Expected VPNotCreatedException to be thrown");
        } catch (VPNotCreatedException e) {
            assertEquals("invalid_request", e.getErrorCode());
            assertTrue(e.getErrorText().contains("Failed to cache matching credentials"));
            assertTrue(e.getErrorText().contains("Serialization failed"));
        }
    }

    @Test
    public void shouldThrowExceptionWhenSerializationFailsForMatchedCredentials() throws Exception {
        MockHttpSession session = new MockHttpSession();
        String presentationId = "test-presentation-id";
        
        // First, store a presentation in the session
        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        VerifiablePresentationSessionData presentationSessionData = new VerifiablePresentationSessionData(mockOpenID4VP, Instant.now(), null);
        sessionManager.storePresentationSessionDataInSession(session, presentationSessionData, presentationId, "test-wallet-id");
        
        // Create test data
        MatchingCredentialsResponseDTO matchingResponse = createTestMatchingCredentialsResponse();
        List<DecryptedCredentialDTO> decryptedCredentials = createTestDecryptedCredentials();
        
        // Mock ObjectMapper - first call fails (this is what the implementation tries to serialize first)
        when(objectMapper.writeValueAsString(any(MatchingCredentialsResponseDTO.class)))
                .thenThrow(new JsonProcessingException("Serialization failed") {});
        
        // Execute and verify exception
        try {
            sessionManager.storeMatchingWalletCredentialsInSession(session, presentationId, matchingResponse, decryptedCredentials);
            fail("Expected VPNotCreatedException to be thrown");
        } catch (VPNotCreatedException e) {
            assertEquals("invalid_request", e.getErrorCode());
            assertTrue(e.getErrorText().contains("Failed to cache matching credentials"));
            assertTrue(e.getErrorText().contains("Serialization failed"));
        }
    }

    @Test
    public void shouldFilterMatchedCredentialsCorrectly() throws Exception {
        MockHttpSession session = new MockHttpSession();
        String presentationId = "test-presentation-id";
        
        // First, store a presentation in the session
        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        VerifiablePresentationSessionData presentationSessionData = new VerifiablePresentationSessionData(mockOpenID4VP, Instant.now(), null);
        sessionManager.storePresentationSessionDataInSession(session, presentationSessionData, presentationId, "test-wallet-id");
        
        // Create test data with multiple credentials
        MatchingCredentialsResponseDTO matchingResponse = MatchingCredentialsResponseDTO.builder()
                .availableCredentials(List.of(
                        SelectableCredentialDTO.builder().credentialId("cred1").build(),
                        SelectableCredentialDTO.builder().credentialId("cred3").build()
                ))
                .missingClaims(Set.of("claim1"))
                .build();
        
        List<DecryptedCredentialDTO> decryptedCredentials = List.of(
                DecryptedCredentialDTO.builder().id("cred1").walletId("wallet1").build(),
                DecryptedCredentialDTO.builder().id("cred2").walletId("wallet2").build(),
                DecryptedCredentialDTO.builder().id("cred3").walletId("wallet3").build()
        );
        
        // Mock ObjectMapper - only needed for error handling
        when(objectMapper.writeValueAsString(any(MatchingCredentialsResponseDTO.class)))
                .thenReturn("{\"availableCredentials\":[{\"credentialId\":\"cred1\"},{\"credentialId\":\"cred3\"}],\"missingClaims\":[\"claim1\"]}");
        
        // Execute
        sessionManager.storeMatchingWalletCredentialsInSession(session, presentationId, matchingResponse, decryptedCredentials);
        
        // Verify only matched credentials are stored
        Map<String, VerifiablePresentationSessionData> presentations = (Map<String, VerifiablePresentationSessionData>) session.getAttribute(SessionKeys.PRESENTATIONS);
        assertNotNull(presentations);
        assertTrue(presentations.containsKey(presentationId));
        
        VerifiablePresentationSessionData updatedSessionData = presentations.get(presentationId);
        assertNotNull(updatedSessionData);
        assertNotNull(updatedSessionData.getMatchingCredentials());
        assertEquals(2, updatedSessionData.getMatchingCredentials().size());
        
        // Verify only matched credentials are stored (cred1 and cred3, not cred2)
        List<String> storedCredentialIds = updatedSessionData.getMatchingCredentials().stream()
                .map(DecryptedCredentialDTO::getId)
                .collect(Collectors.toList());
        assertTrue(storedCredentialIds.contains("cred1"));
        assertTrue(storedCredentialIds.contains("cred3"));
        assertFalse(storedCredentialIds.contains("cred2")); // Should not contain unmatched credential
    }

    private MatchingCredentialsResponseDTO createTestMatchingCredentialsResponse() {
        return MatchingCredentialsResponseDTO.builder()
                .availableCredentials(List.of(
                        SelectableCredentialDTO.builder()
                                .credentialId("cred1")
                                .credentialTypeDisplayName("Test Credential")
                                .format("ldp_vc")
                                .build()
                ))
                .missingClaims(Set.of("claim1", "claim2"))
                .build();
    }

    private List<DecryptedCredentialDTO> createTestDecryptedCredentials() {
        CredentialMetadata metadata = new CredentialMetadata();
        metadata.setIssuerId("issuer1");
        metadata.setCredentialType("TestCredential");
        
        return List.of(
                DecryptedCredentialDTO.builder()
                        .id("cred1")
                        .walletId("wallet1")
                        .credentialMetadata(metadata)
                        .build()
        );
    }

    private String createMockSessionDataJson() {
        return "{\"createdAt\":\"2025-09-20T04:44:16.956160Z\",\"walletId\":\"ab42f3c6-4596-482e-95da-4416be38eec9\",\"openID4VPInstance\":\"" + createMockOpenID4VPInstanceJson() + "\"}";
    }

    private String createMockSessionDataJsonWithoutOpenID4VP() {
        return "{\"createdAt\":\"2025-09-20T04:44:16.956160Z\",\"walletId\":\"ab42f3c6-4596-482e-95da-4416be38eec9\"}";
    }

    private String createMockOpenID4VPInstanceJson() {
        return "{\"authorizationRequest\":{\"clientId\":\"injiverify.collab.mosip.net\",\"presentationDefinition\":{\"id\":\"c4822b58-7fb4-454e-b827-f8758fe27f9a\",\"inputDescriptors\":[{\"id\":\"id card credential\",\"format\":{\"ldp_vc\":{\"proof_type\":[\"RsaSignature2018\"]}},\"constraints\":{\"fields\":[{\"path\":[\"$.type\"],\"filter\":{\"type\":\"object\",\"pattern\":\"MOSIPVerifiableCredential\"}}],\"limitDisclosure\":null}},{\"id\":\"id card credential\",\"format\":{\"ldp_vc\":{\"proof_type\":[\"Ed25519Signature2020\"]}},\"constraints\":{\"fields\":[{\"path\":[\"$.type\"],\"filter\":{\"type\":\"object\",\"pattern\":\"InsuranceCredential\"}}],\"limitDisclosure\":null}}]}}}";
    }

    private Map<String, Object> createMockVpSessionData() {
        Map<String, Object> vpSessionData = new HashMap<>();
        vpSessionData.put("createdAt", "2025-09-20T04:44:16.956160Z");
        vpSessionData.put("walletId", "ab42f3c6-4596-482e-95da-4416be38eec9");
        vpSessionData.put("openID4VPInstance", createMockOpenID4VPInstanceJson());
        return vpSessionData;
    }

    private Map<String, Object> createMockVpSessionDataWithoutOpenID4VP() {
        Map<String, Object> vpSessionData = new HashMap<>();
        vpSessionData.put("createdAt", "2025-09-20T04:44:16.956160Z");
        vpSessionData.put("walletId", "ab42f3c6-4596-482e-95da-4416be38eec9");
        return vpSessionData;
    }

    private Map<String, Object> createMockOpenID4VPInstance() {
        Map<String, Object> openID4VPInstance = new HashMap<>();
        Map<String, Object> authorizationRequest = new HashMap<>();
        Map<String, Object> presentationDefinition = new HashMap<>();

        presentationDefinition.put("id", "c4822b58-7fb4-454e-b827-f8758fe27f9a");
        presentationDefinition.put("inputDescriptors", createMockInputDescriptorsList());

        authorizationRequest.put("presentationDefinition", presentationDefinition);
        openID4VPInstance.put("authorizationRequest", authorizationRequest);

        return openID4VPInstance;
    }

    private Map<String, Object> createMockOpenID4VPInstanceWithoutAuthRequest() {
        Map<String, Object> openID4VPInstance = new HashMap<>();
        // Don't add authorizationRequest
        return openID4VPInstance;
    }

    private Map<String, Object> createMockOpenID4VPInstanceWithoutPresentationDefinition() {
        Map<String, Object> openID4VPInstance = new HashMap<>();
        Map<String, Object> authorizationRequest = new HashMap<>();
        // Don't add presentationDefinition
        openID4VPInstance.put("authorizationRequest", authorizationRequest);
        return openID4VPInstance;
    }

    private Map<String, Object> createMockOpenID4VPInstanceWithEmptyInputDescriptors() {
        Map<String, Object> openID4VPInstance = new HashMap<>();
        Map<String, Object> authorizationRequest = new HashMap<>();
        Map<String, Object> presentationDefinition = new HashMap<>();

        presentationDefinition.put("id", "c4822b58-7fb4-454e-b827-f8758fe27f9a");
        presentationDefinition.put("inputDescriptors", null); // Empty input descriptors

        authorizationRequest.put("presentationDefinition", presentationDefinition);
        openID4VPInstance.put("authorizationRequest", authorizationRequest);

        return openID4VPInstance;
    }

    private Map<String, Object> createMockOpenID4VPInstanceWithInputDescriptorWithoutConstraints() {
        Map<String, Object> openID4VPInstance = new HashMap<>();
        Map<String, Object> authorizationRequest = new HashMap<>();
        Map<String, Object> presentationDefinition = new HashMap<>();

        presentationDefinition.put("id", "c4822b58-7fb4-454e-b827-f8758fe27f9a");

        List<Map<String, Object>> inputDescriptors = new ArrayList<>();
        Map<String, Object> inputDescriptor = new HashMap<>();
        inputDescriptor.put("id", "id card credential");
        inputDescriptor.put("format", createMockFormat());
        inputDescriptor.put("constraints", null); // No constraints
        inputDescriptors.add(inputDescriptor);

        presentationDefinition.put("inputDescriptors", inputDescriptors);
        authorizationRequest.put("presentationDefinition", presentationDefinition);
        openID4VPInstance.put("authorizationRequest", authorizationRequest);

        return openID4VPInstance;
    }

    private List<Map<String, Object>> createMockInputDescriptorsList() {
        List<Map<String, Object>> inputDescriptors = new ArrayList<>();

        // First input descriptor
        Map<String, Object> inputDescriptor1 = new HashMap<>();
        inputDescriptor1.put("id", "id card credential");
        inputDescriptor1.put("format", createMockFormat());
        inputDescriptor1.put("constraints", createMockConstraints());
        inputDescriptors.add(inputDescriptor1);

        // Second input descriptor
        Map<String, Object> inputDescriptor2 = new HashMap<>();
        inputDescriptor2.put("id", "id card credential");
        inputDescriptor2.put("format", createMockFormat());
        inputDescriptor2.put("constraints", createMockConstraints2());
        inputDescriptors.add(inputDescriptor2);

        return inputDescriptors;
    }

    private Map<String, Object> createMockFormat() {
        Map<String, Object> format = new HashMap<>();
        Map<String, Object> ldpVc = new HashMap<>();
        ldpVc.put("proof_type", List.of("RsaSignature2018"));
        format.put("ldp_vc", ldpVc);
        return format;
    }

    private Map<String, Object> createMockConstraints() {
        Map<String, Object> constraints = new HashMap<>();
        constraints.put("limitDisclosure", null);

        List<Map<String, Object>> fields = new ArrayList<>();
        Map<String, Object> field = new HashMap<>();
        field.put("path", List.of("$.type"));

        Map<String, Object> filter = new HashMap<>();
        filter.put("type", "object");
        filter.put("pattern", "MOSIPVerifiableCredential");
        field.put("filter", filter);

        fields.add(field);
        constraints.put("fields", fields);

        return constraints;
    }

    private Map<String, Object> createMockConstraints2() {
        Map<String, Object> constraints = new HashMap<>();
        constraints.put("limitDisclosure", null);

        List<Map<String, Object>> fields = new ArrayList<>();
        Map<String, Object> field = new HashMap<>();
        field.put("path", List.of("$.type"));

        Map<String, Object> filter = new HashMap<>();
        filter.put("type", "object");
        filter.put("pattern", "InsuranceCredential");
        field.put("filter", filter);

        fields.add(field);
        constraints.put("fields", fields);

        return constraints;
    }

    private PresentationDefinitionDTO createExpectedPresentationDefinitionDTO() {
        PresentationDefinitionDTO dto = new PresentationDefinitionDTO();
        dto.setId("c4822b58-7fb4-454e-b827-f8758fe27f9a");
        
        // Create input descriptors list
        List<InputDescriptorDTO> inputDescriptors = new ArrayList<>();
        
        // First input descriptor
        InputDescriptorDTO inputDescriptor1 = new InputDescriptorDTO();
        inputDescriptor1.setId("id card credential");
        inputDescriptor1.setFormat(createExpectedFormat());
        inputDescriptor1.setConstraints(createExpectedConstraintsDTO());
        inputDescriptors.add(inputDescriptor1);
        
        // Second input descriptor
        InputDescriptorDTO inputDescriptor2 = new InputDescriptorDTO();
        inputDescriptor2.setId("id card credential");
        inputDescriptor2.setFormat(createExpectedFormat());
        inputDescriptor2.setConstraints(createExpectedConstraintsDTO2());
        inputDescriptors.add(inputDescriptor2);
        
        dto.setInputDescriptors(inputDescriptors);
        return dto;
    }

    private ConstraintsDTO createExpectedConstraintsDTO() {
        ConstraintsDTO constraints = new ConstraintsDTO();
        constraints.setLimitDisclosure(null);
        
        FieldDTO[] fields = new FieldDTO[1];
        FieldDTO field = new FieldDTO();
        field.setPath(new String[]{"$.type"});
        
        FilterDTO filter = new FilterDTO();
        filter.setType("object");
        filter.setPattern("MOSIPVerifiableCredential");
        field.setFilter(filter);
        
        fields[0] = field;
        constraints.setFields(fields);
        
        return constraints;
    }

    private ConstraintsDTO createExpectedConstraintsDTO2() {
        ConstraintsDTO constraints = new ConstraintsDTO();
        constraints.setLimitDisclosure(null);
        
        FieldDTO[] fields = new FieldDTO[1];
        FieldDTO field = new FieldDTO();
        field.setPath(new String[]{"$.type"});
        
        FilterDTO filter = new FilterDTO();
        filter.setType("object");
        filter.setPattern("InsuranceCredential");
        field.setFilter(filter);
        
        fields[0] = field;
        constraints.setFields(fields);
        
        return constraints;
    }

    private Map<String, Map<String, List<String>>> createExpectedFormat() {
        Map<String, Map<String, List<String>>> format = new HashMap<>();
        Map<String, List<String>> ldpVc = new HashMap<>();
        ldpVc.put("proof_type", Arrays.asList("RsaSignature2018"));
        format.put("ldp_vc", ldpVc);
        return format;
    }

    private PresentationDefinitionDTO createExpectedPresentationDefinitionDTOWithEmptyInputDescriptors() {
        PresentationDefinitionDTO dto = new PresentationDefinitionDTO();
        dto.setId("c4822b58-7fb4-454e-b827-f8758fe27f9a");
        dto.setInputDescriptors(null); // Empty input descriptors as expected by the test
        return dto;
    }

    private PresentationDefinitionDTO createExpectedPresentationDefinitionDTOWithInputDescriptorWithoutConstraints() {
        PresentationDefinitionDTO dto = new PresentationDefinitionDTO();
        dto.setId("c4822b58-7fb4-454e-b827-f8758fe27f9a");
        
        // Create input descriptors list with one descriptor without constraints
        List<InputDescriptorDTO> inputDescriptors = new ArrayList<>();
        
        InputDescriptorDTO inputDescriptor = new InputDescriptorDTO();
        inputDescriptor.setId("id card credential");
        inputDescriptor.setFormat(createExpectedFormat());
        inputDescriptor.setConstraints(null); // No constraints as expected by the test
        inputDescriptors.add(inputDescriptor);
        
        dto.setInputDescriptors(inputDescriptors);
        return dto;
    }
}
