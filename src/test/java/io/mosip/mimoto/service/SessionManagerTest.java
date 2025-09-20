package io.mosip.mimoto.service;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.mimoto.UserMetadataDTO;
import io.mosip.mimoto.dto.openid.presentation.InputDescriptorDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationDefinitionDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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

        assertEquals(provider, session.getAttribute("clientRegistrationId"));
        assertEquals(userMetadataDTO, session.getAttribute(SessionKeys.USER_METADATA));
        assertEquals(userId, session.getAttribute(SessionKeys.USER_ID));
    }

    @Test
    public void shouldCreateAndStorePresentationDetailsInSession() throws Exception {
        Instant fixedInstant = Instant.parse("2025-09-08T12:34:56Z");
        MockHttpSession session = new MockHttpSession();
        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        VerifiablePresentationSessionData presentationSessionData = new VerifiablePresentationSessionData(mockOpenID4VP, fixedInstant);
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
        String expectedSessionPresentationData1 = "{\"createdAt\":\"2025-09-08T12:34:56Z\",\"walletId\":\"wallet123\",\"openID4VPInstance\":\"{\\\"mock\\\":\\\"json1\\\"}\"}", expectedSessionPresentationData2 = "{\"createdAt\":\"2025-09-08T12:34:56Z\",\"walletId\":\"wallet456\",\"openID4VPInstance\":\"{\\\"mock\\\":\\\"json2\\\"}\"}";

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

        when(objectMapper.writeValueAsString(eq(mockOpenID4VP))).thenThrow(new JsonParseException("Error occurred while serializing OpenID4VP"));

        try {
            sessionManager.storePresentationSessionDataInSession(session, sessionData, "123e4567-e89b-12d3-a456-426614174000", "wallet123");
            fail("Expected VPNotCreatedException to be thrown");
        } catch (VPNotCreatedException e) {
            String expectedErrorMessage = "Failed to serialize presentation data - Error occurred while serializing OpenID4VP";
            assertEquals("invalid_request", e.getErrorCode());
            assertEquals(expectedErrorMessage, e.getErrorText());
        }
    }

    @Test
    public void shouldReturnPresentationDefinitionFromSessionSuccessfully() throws Exception {

        String presentationId = "test-presentation-id";
        MockHttpSession session = new MockHttpSession();

        Map<String, String> presentations = new HashMap<>();
        String sessionDataJson = createMockSessionDataJson();
        presentations.put(presentationId, sessionDataJson);
        session.setAttribute("presentations", presentations);

        when(objectMapper.readValue(eq(sessionDataJson), eq(Map.class))).thenReturn(createMockVpSessionData());
        when(objectMapper.readValue(eq(createMockOpenID4VPInstanceJson()), eq(Map.class))).thenReturn(createMockOpenID4VPInstance());


        PresentationDefinitionDTO result = sessionManager.getPresentationDefinitionFromSession(session, presentationId);


        assertNotNull(result);
        assertEquals("c4822b58-7fb4-454e-b827-f8758fe27f9a", result.getId());
        assertNotNull(result.getInputDescriptors());
        assertEquals(2, result.getInputDescriptors().size());

        InputDescriptorDTO firstDescriptor = result.getInputDescriptors().get(0);
        assertEquals("id card credential", firstDescriptor.getId());
        assertNotNull(firstDescriptor.getFormat());
        assertNotNull(firstDescriptor.getConstraints());
        assertEquals(1, firstDescriptor.getConstraints().getFields().length);
    }

    @Test
    public void shouldReturnNullWhenNoPresentationsInSession() throws Exception {

        String presentationId = "test-presentation-id";
        MockHttpSession session = new MockHttpSession();

        PresentationDefinitionDTO result = sessionManager.getPresentationDefinitionFromSession(session, presentationId);

        assertNull(result);
    }

    @Test
    public void shouldReturnNullWhenPresentationIdNotFound() throws Exception {

        String presentationId = "non-existent-id";
        MockHttpSession session = new MockHttpSession();

        Map<String, String> presentations = new HashMap<>();
        presentations.put("other-id", "some-data");
        session.setAttribute("presentations", presentations);

        PresentationDefinitionDTO result = sessionManager.getPresentationDefinitionFromSession(session, presentationId);

        assertNull(result);
    }

    @Test
    public void shouldReturnNullWhenOpenID4VPInstanceIsNull() throws Exception {

        String presentationId = "test-presentation-id";
        MockHttpSession session = new MockHttpSession();

        Map<String, String> presentations = new HashMap<>();
        String sessionDataJson = createMockSessionDataJsonWithoutOpenID4VP();
        presentations.put(presentationId, sessionDataJson);
        session.setAttribute("presentations", presentations);

        when(objectMapper.readValue(eq(sessionDataJson), eq(Map.class))).thenReturn(createMockVpSessionDataWithoutOpenID4VP());

        PresentationDefinitionDTO result = sessionManager.getPresentationDefinitionFromSession(session, presentationId);

        assertNull(result);
    }

    @Test
    public void shouldReturnNullWhenAuthorizationRequestIsNull() throws Exception {

        String presentationId = "test-presentation-id";
        MockHttpSession session = new MockHttpSession();

        Map<String, String> presentations = new HashMap<>();
        String sessionDataJson = createMockSessionDataJson();
        presentations.put(presentationId, sessionDataJson);
        session.setAttribute("presentations", presentations);

        when(objectMapper.readValue(eq(sessionDataJson), eq(Map.class))).thenReturn(createMockVpSessionData());
        when(objectMapper.readValue(eq(createMockOpenID4VPInstanceJson()), eq(Map.class))).thenReturn(createMockOpenID4VPInstanceWithoutAuthRequest());

        PresentationDefinitionDTO result = sessionManager.getPresentationDefinitionFromSession(session, presentationId);

        assertNull(result);
    }

    @Test
    public void shouldReturnNullWhenPresentationDefinitionIsNull() throws Exception {

        String presentationId = "test-presentation-id";
        MockHttpSession session = new MockHttpSession();

        Map<String, String> presentations = new HashMap<>();
        String sessionDataJson = createMockSessionDataJson();
        presentations.put(presentationId, sessionDataJson);
        session.setAttribute("presentations", presentations);

        when(objectMapper.readValue(eq(sessionDataJson), eq(Map.class))).thenReturn(createMockVpSessionData());
        when(objectMapper.readValue(eq(createMockOpenID4VPInstanceJson()), eq(Map.class))).thenReturn(createMockOpenID4VPInstanceWithoutPresentationDefinition());

        PresentationDefinitionDTO result = sessionManager.getPresentationDefinitionFromSession(session, presentationId);

        assertNull(result);
    }

    @Test
    public void shouldHandleJsonProcessingExceptionGracefully() throws Exception {

        String presentationId = "test-presentation-id";
        MockHttpSession session = new MockHttpSession();

        Map<String, String> presentations = new HashMap<>();
        String sessionDataJson = "invalid-json";
        presentations.put(presentationId, sessionDataJson);
        session.setAttribute("presentations", presentations);

        when(objectMapper.readValue(eq(sessionDataJson), eq(Map.class))).thenThrow(new JsonProcessingException("Invalid JSON") {
        });

        PresentationDefinitionDTO result = sessionManager.getPresentationDefinitionFromSession(session, presentationId);

        assertNull(result);
    }

    @Test
    public void shouldHandleOpenID4VPInstanceJsonProcessingExceptionGracefully() throws Exception {

        String presentationId = "test-presentation-id";
        MockHttpSession session = new MockHttpSession();

        Map<String, String> presentations = new HashMap<>();
        String sessionDataJson = createMockSessionDataJson();
        presentations.put(presentationId, sessionDataJson);
        session.setAttribute("presentations", presentations);

        when(objectMapper.readValue(eq(sessionDataJson), eq(Map.class))).thenReturn(createMockVpSessionData());
        when(objectMapper.readValue(eq(createMockOpenID4VPInstanceJson()), eq(Map.class))).thenThrow(new JsonProcessingException("Invalid OpenID4VP JSON") {
        });

        PresentationDefinitionDTO result = sessionManager.getPresentationDefinitionFromSession(session, presentationId);

        assertNull(result);
    }

    @Test
    public void shouldHandleEmptyInputDescriptorsList() throws Exception {

        String presentationId = "test-presentation-id";
        MockHttpSession session = new MockHttpSession();

        Map<String, String> presentations = new HashMap<>();
        String sessionDataJson = createMockSessionDataJson();
        presentations.put(presentationId, sessionDataJson);
        session.setAttribute("presentations", presentations);

        when(objectMapper.readValue(eq(sessionDataJson), eq(Map.class))).thenReturn(createMockVpSessionData());
        when(objectMapper.readValue(eq(createMockOpenID4VPInstanceJson()), eq(Map.class))).thenReturn(createMockOpenID4VPInstanceWithEmptyInputDescriptors());

        PresentationDefinitionDTO result = sessionManager.getPresentationDefinitionFromSession(session, presentationId);

        assertNotNull(result);
        assertEquals("c4822b58-7fb4-454e-b827-f8758fe27f9a", result.getId());
        assertNull(result.getInputDescriptors());
    }

    @Test
    public void shouldHandleInputDescriptorWithoutConstraints() throws Exception {

        String presentationId = "test-presentation-id";
        MockHttpSession session = new MockHttpSession();

        Map<String, String> presentations = new HashMap<>();
        String sessionDataJson = createMockSessionDataJson();
        presentations.put(presentationId, sessionDataJson);
        session.setAttribute("presentations", presentations);

        when(objectMapper.readValue(eq(sessionDataJson), eq(Map.class))).thenReturn(createMockVpSessionData());
        when(objectMapper.readValue(eq(createMockOpenID4VPInstanceJson()), eq(Map.class))).thenReturn(createMockOpenID4VPInstanceWithInputDescriptorWithoutConstraints());

        PresentationDefinitionDTO result = sessionManager.getPresentationDefinitionFromSession(session, presentationId);
        
        assertNotNull(result);
        assertEquals(1, result.getInputDescriptors().size());
        InputDescriptorDTO descriptor = result.getInputDescriptors().get(0);
        assertEquals("id card credential", descriptor.getId());
        assertNull(descriptor.getConstraints());
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
}
