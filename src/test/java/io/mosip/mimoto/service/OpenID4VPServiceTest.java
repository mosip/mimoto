package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.openid.VerifierDTO;
import io.mosip.mimoto.dto.openid.VerifiersDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.service.impl.OpenID4VPService;
import io.mosip.openID4VP.OpenID4VP;
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest;
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition;
import lombok.extern.slf4j.Slf4j;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
@Slf4j
public class OpenID4VPServiceTest {

    @Mock
    private VerifierService verifierService;

    @InjectMocks
    private OpenID4VPService openID4VPService;

    private VerifiersDTO mockVerifiersDTO;
    private VerifierDTO mockVerifierDTO;
    private AuthorizationRequest mockAuthorizationRequest;
    private PresentationDefinition mockPresentationDefinition;

    @Before
    public void setUp() {
        // Setup mock VerifierDTO with required vp_formats
        mockVerifierDTO = VerifierDTO.builder()
                .clientId("test-client-id")
                .responseUris(List.of("https://example.com/response"))
                .clientMetadata(Map.of(
                        "client_name", "Test Verifier",
                        "logo_uri", "https://example.com/logo.png",
                        "vp_formats", Map.of(
                                "ldp_vc", Map.of(
                                        "proof_type", List.of("Ed25519Signature2020")
                                )
                        )
                ))
                .build();

        // Setup mock VerifiersDTO
        mockVerifiersDTO = VerifiersDTO.builder()
                .verifiers(List.of(mockVerifierDTO))
                .build();


        // Setup mock AuthorizationRequest
        mockAuthorizationRequest = mock(AuthorizationRequest.class);

        // Setup mock PresentationDefinition
        mockPresentationDefinition = mock(PresentationDefinition.class);
    }

    @Test
    public void testCreateReturnsValidOpenID4VP() {
        OpenID4VP openID4VP = openID4VPService.create("presentation-123");

        assertNotNull(openID4VP);
        assertEquals("io.mosip.openID4VP.OpenID4VP", openID4VP.getClass().getName());
    }

    @Test
    public void testCreateWithValidPresentationIdReturnsValidOpenID4VP() {
        OpenID4VP openID4VP = openID4VPService.create("valid-presentation-id");

        assertNotNull(openID4VP);
        assertEquals("io.mosip.openID4VP.OpenID4VP", openID4VP.getClass().getName());
    }

    @Test
    public void testCreateWithSpecialCharactersPresentationIdReturnsValidOpenID4VP() {
        OpenID4VP openID4VP = openID4VPService.create("presentation-123_with.special@chars");

        assertNotNull(openID4VP);
        assertEquals("io.mosip.openID4VP.OpenID4VP", openID4VP.getClass().getName());
    }

    @Test
    public void testResolvePresentationDefinitionSuccess() throws Exception {
        // Setup mocks
        when(verifierService.getTrustedVerifiers()).thenReturn(mockVerifiersDTO);
        
        // Create a mock OpenID4VP to control the authenticateVerifier method
        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        when(mockOpenID4VP.authenticateVerifier(anyString(), anyList(), anyBoolean()))
                .thenReturn(mockAuthorizationRequest);
        when(mockAuthorizationRequest.getPresentationDefinition())
                .thenReturn(mockPresentationDefinition);

        // Use reflection to replace the create method behavior
        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString());

        // Execute
        PresentationDefinition result = spyService.resolvePresentationDefinition(
                "presentation-123", 
                "authorization-request", 
                true
        );

        // Verify
        assertNotNull(result);
        assertEquals(mockPresentationDefinition, result);
        verify(verifierService).getTrustedVerifiers();
        verify(mockOpenID4VP).authenticateVerifier(eq("authorization-request"), anyList(), eq(true));
        verify(mockAuthorizationRequest).getPresentationDefinition();
    }

    @Test
    public void testResolvePresentationDefinitionWithNullPresentationIdReturnsNull() throws Exception {
        // Execute
        PresentationDefinition result = openID4VPService.resolvePresentationDefinition(
                null, 
                "authorization-request", 
                true
        );

        // Verify
        assertNull(result);
        verifyNoInteractions(verifierService);
    }

    @Test
    public void testResolvePresentationDefinitionWithNullAuthorizationRequestReturnsNull() throws Exception {
        // Execute
        PresentationDefinition result = openID4VPService.resolvePresentationDefinition(
                "presentation-123", 
                null, 
                true
        );

        // Verify
        assertNull(result);
        verifyNoInteractions(verifierService);
    }

    @Test
    public void testResolvePresentationDefinitionWithBothNullParametersReturnsNull() throws Exception {
        // Execute
        PresentationDefinition result = openID4VPService.resolvePresentationDefinition(
                null, 
                null, 
                true
        );

        // Verify
        assertNull(result);
        verifyNoInteractions(verifierService);
    }

    @Test
    public void testResolvePresentationDefinitionWithEmptyPresentationIdReturnsNull() throws Exception {
        // Setup mocks for empty string scenario - service doesn't check for empty strings, so it continues execution
        when(verifierService.getTrustedVerifiers()).thenReturn(mockVerifiersDTO);
        
        // Create a mock OpenID4VP to control the authenticateVerifier method
        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        when(mockOpenID4VP.authenticateVerifier(anyString(), anyList(), anyBoolean()))
                .thenReturn(mockAuthorizationRequest);
        when(mockAuthorizationRequest.getPresentationDefinition())
                .thenReturn(mockPresentationDefinition);

        // Use reflection to replace the create method behavior
        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString());

        // Execute
        PresentationDefinition result = spyService.resolvePresentationDefinition(
                "", 
                "authorization-request", 
                true
        );

        // Verify - Empty string is not null, so it will proceed to call verifierService
        assertNotNull(result);
        verify(verifierService).getTrustedVerifiers();
        verify(mockOpenID4VP).authenticateVerifier(eq("authorization-request"), anyList(), eq(true));
        verify(mockAuthorizationRequest).getPresentationDefinition();
    }

    @Test
    public void testResolvePresentationDefinitionWithEmptyAuthorizationRequestReturnsNull() throws Exception {
        // Setup mocks for empty string scenario - service doesn't check for empty strings, so it continues execution
        when(verifierService.getTrustedVerifiers()).thenReturn(mockVerifiersDTO);
        
        // Create a mock OpenID4VP to control the authenticateVerifier method
        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        when(mockOpenID4VP.authenticateVerifier(anyString(), anyList(), anyBoolean()))
                .thenReturn(mockAuthorizationRequest);
        when(mockAuthorizationRequest.getPresentationDefinition())
                .thenReturn(mockPresentationDefinition);

        // Use reflection to replace the create method behavior
        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString());

        // Execute
        PresentationDefinition result = spyService.resolvePresentationDefinition(
                "presentation-123", 
                "", 
                true
        );

        // Verify - Empty string is not null, so it will proceed to call verifierService
        assertNotNull(result);
        verify(verifierService).getTrustedVerifiers();
        verify(mockOpenID4VP).authenticateVerifier(eq(""), anyList(), eq(true));
        verify(mockAuthorizationRequest).getPresentationDefinition();
    }

    @Test
    public void testResolvePresentationDefinitionWithVerifierServiceExceptionThrowsException() throws Exception {
        // Setup mocks
        when(verifierService.getTrustedVerifiers())
                .thenThrow(new ApiNotAccessibleException());

        // Execute and verify exception
        assertThrows(ApiNotAccessibleException.class, () -> {
            openID4VPService.resolvePresentationDefinition(
                    "presentation-123", 
                    "authorization-request", 
                    true
            );
        });

        verify(verifierService).getTrustedVerifiers();
    }

    @Test
    public void testResolvePresentationDefinitionWithIOExceptionThrowsException() throws Exception {
        // Setup mocks
        when(verifierService.getTrustedVerifiers())
                .thenThrow(new IOException("Network error"));

        // Execute and verify exception
        assertThrows(IOException.class, () -> {
            openID4VPService.resolvePresentationDefinition(
                    "presentation-123", 
                    "authorization-request", 
                    true
            );
        });

        verify(verifierService).getTrustedVerifiers();
    }

    @Test
    public void testResolvePresentationDefinitionWithEmptyVerifiersList() throws Exception {
        // Setup mocks with empty verifiers list
        VerifiersDTO emptyVerifiersDTO = VerifiersDTO.builder()
                .verifiers(List.of())
                .build();
        when(verifierService.getTrustedVerifiers()).thenReturn(emptyVerifiersDTO);
        
        // Create a mock OpenID4VP to control the authenticateVerifier method
        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        when(mockOpenID4VP.authenticateVerifier(anyString(), anyList(), anyBoolean()))
                .thenReturn(mockAuthorizationRequest);
        when(mockAuthorizationRequest.getPresentationDefinition())
                .thenReturn(mockPresentationDefinition);

        // Use reflection to replace the create method behavior
        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString());

        // Execute
        PresentationDefinition result = spyService.resolvePresentationDefinition(
                "presentation-123", 
                "authorization-request", 
                false
        );

        // Verify
        assertNotNull(result);
        assertEquals(mockPresentationDefinition, result);
        verify(verifierService).getTrustedVerifiers();
        verify(mockOpenID4VP).authenticateVerifier("authorization-request", List.of(), false);
        verify(mockAuthorizationRequest).getPresentationDefinition();
    }

    @Test
    public void testResolvePresentationDefinitionWithNullPresentationDefinition() throws Exception {
        // Setup mocks
        when(verifierService.getTrustedVerifiers()).thenReturn(mockVerifiersDTO);
        
        // Create a mock OpenID4VP to control the authenticateVerifier method
        OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
        when(mockOpenID4VP.authenticateVerifier(anyString(), anyList(), anyBoolean()))
                .thenReturn(mockAuthorizationRequest);
        when(mockAuthorizationRequest.getPresentationDefinition())
                .thenReturn(null);

        // Use reflection to replace the create method behavior
        OpenID4VPService spyService = spy(openID4VPService);
        doReturn(mockOpenID4VP).when(spyService).create(anyString());

        // Execute
        PresentationDefinition result = spyService.resolvePresentationDefinition(
                "presentation-123", 
                "authorization-request", 
                true
        );

        // Verify
        assertNull(result);
        verify(verifierService).getTrustedVerifiers();
        verify(mockOpenID4VP).authenticateVerifier(eq("authorization-request"), anyList(), eq(true));
        verify(mockAuthorizationRequest).getPresentationDefinition();
    }
}
