package io.mosip.mimoto.service;

import com.nimbusds.jose.JOSEException;
import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.RejectedVerifierDTO;
import io.mosip.mimoto.dto.SubmitPresentationRequestDTO;
import io.mosip.mimoto.dto.SubmitPresentationResponseDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.DecryptionException;
import io.mosip.mimoto.exception.KeyGenerationException;
import io.mosip.mimoto.exception.VPErrorNotSentException;
import io.mosip.mimoto.service.impl.PresentationActionServiceImpl;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.io.IOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class PresentationActionServiceTest {

    @InjectMocks
    private PresentationActionServiceImpl presentationActionService;

    @Mock
    private PresentationSubmissionService presentationSubmissionService;

    @Mock
    private PresentationService presentationService;

    private static final String WALLET_ID = "wallet123";
    private static final String PRESENTATION_ID = "presentation123";
    private static final String BASE64_KEY = "encodedKey123";
    private static final String AUTH_REQUEST = "client_id=test&nonce=123";

    private VerifiablePresentationSessionData sessionData;

    @Before
    public void setup() {
        MockitoAnnotations.openMocks(this);
        sessionData = new VerifiablePresentationSessionData(
                PRESENTATION_ID,
                AUTH_REQUEST,
                Instant.now(),
                true,
                null
        );
    }

    @Test
    public void testHandlePresentationAction_SubmissionSuccess() throws Exception {
        // Given
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(Arrays.asList("cred-123", "cred-456"))
                .build();

        SubmitPresentationResponseDTO expectedResponse = SubmitPresentationResponseDTO.builder()
                .presentationId(PRESENTATION_ID)
                .status("SUCCESS")
                .message("Presentation successfully submitted and shared with verifier")
                .build();

        when(presentationSubmissionService.submitPresentation(
                eq(sessionData), eq(WALLET_ID), eq(PRESENTATION_ID), eq(request), eq(BASE64_KEY)))
                .thenReturn(expectedResponse);

        // When
        ResponseEntity<?> response = presentationActionService.handlePresentationAction(
                WALLET_ID, PRESENTATION_ID, request, sessionData, BASE64_KEY);

        // Then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertTrue(response.getBody() instanceof SubmitPresentationResponseDTO);
        SubmitPresentationResponseDTO responseBody = (SubmitPresentationResponseDTO) response.getBody();
        assertEquals(PRESENTATION_ID, responseBody.getPresentationId());
        assertEquals("SUCCESS", responseBody.getStatus());

        verify(presentationSubmissionService, times(1)).submitPresentation(
                eq(sessionData), eq(WALLET_ID), eq(PRESENTATION_ID), eq(request), eq(BASE64_KEY));
        verify(presentationService, never()).rejectVerifier(any(), any(), any());
    }

    @Test
    public void testHandlePresentationAction_RejectionSuccess() throws Exception {
        // Given
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .errorCode("access_denied")
                .errorMessage("User denied authorization to share credentials")
                .build();

        RejectedVerifierDTO expectedResponse = new RejectedVerifierDTO(
                "success",
                null,
                "Presentation request rejected. An OpenID4VP error response has been sent to the verifier."
        );

        when(presentationService.rejectVerifier(eq(WALLET_ID), eq(sessionData), any(ErrorDTO.class)))
                .thenReturn(expectedResponse);

        // When
        ResponseEntity<?> response = presentationActionService.handlePresentationAction(
                WALLET_ID, PRESENTATION_ID, request, sessionData, BASE64_KEY);

        // Then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertTrue(response.getBody() instanceof RejectedVerifierDTO);
        RejectedVerifierDTO responseBody = (RejectedVerifierDTO) response.getBody();
        assertEquals("success", responseBody.getStatus());

        verify(presentationService, times(1)).rejectVerifier(eq(WALLET_ID), eq(sessionData), any(ErrorDTO.class));
        verify(presentationSubmissionService, never()).submitPresentation(any(), any(), any(), any(), any());
    }

    @Test
    public void testHandlePresentationAction_InvalidRequest_NoCredentialsOrError() throws Exception {
        // Given - request with neither credentials nor error
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .build();

        // When
        ResponseEntity<?> response = presentationActionService.handlePresentationAction(
                WALLET_ID, PRESENTATION_ID, request, sessionData, BASE64_KEY);

        // Then - should return bad request error
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        verify(presentationSubmissionService, never()).submitPresentation(any(), any(), any(), any(), any());
        verify(presentationService, never()).rejectVerifier(any(), any(), any());
    }

    @Test
    public void testHandlePresentationAction_InvalidRequest_EmptyCredentials() throws Exception {
        // Given - request with empty credentials list
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(Collections.emptyList())
                .build();

        // When
        ResponseEntity<?> response = presentationActionService.handlePresentationAction(
                WALLET_ID, PRESENTATION_ID, request, sessionData, BASE64_KEY);

        // Then - should return bad request error
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        verify(presentationSubmissionService, never()).submitPresentation(any(), any(), any(), any(), any());
        verify(presentationService, never()).rejectVerifier(any(), any(), any());
    }

    @Test
    public void testHandlePresentationAction_Submission_NullWalletKey() {
        // Given
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(Arrays.asList("cred-123"))
                .build();

        // When - wallet key is null
        ResponseEntity<?> response = presentationActionService.handlePresentationAction(
                WALLET_ID, PRESENTATION_ID, request, sessionData, null);

        // Then - should return bad request error
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    }

    @Test
    public void testHandlePresentationAction_Submission_EmptyWalletKey() {
        // Given
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(Arrays.asList("cred-123"))
                .build();

        // When - wallet key is empty
        ResponseEntity<?> response = presentationActionService.handlePresentationAction(
                WALLET_ID, PRESENTATION_ID, request, sessionData, "");

        // Then - should return bad request error
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    }

    @Test
    public void testHandlePresentationAction_Submission_JOSEException() throws Exception {
        // Given
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(Arrays.asList("cred-123"))
                .build();

        when(presentationSubmissionService.submitPresentation(
                any(), any(), any(), any(), any()))
                .thenThrow(new JOSEException("JWT signing failed"));

        // When
        ResponseEntity<?> response = presentationActionService.handlePresentationAction(
                WALLET_ID, PRESENTATION_ID, request, sessionData, BASE64_KEY);

        // Then - should return internal server error
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
    }

    @Test
    public void testHandlePresentationAction_Submission_KeyGenerationException() throws Exception {
        // Given
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(Arrays.asList("cred-123"))
                .build();

        when(presentationSubmissionService.submitPresentation(
                any(), any(), any(), any(), any()))
                .thenThrow(new KeyGenerationException("Key generation failed", null));

        // When
        ResponseEntity<?> response = presentationActionService.handlePresentationAction(
                WALLET_ID, PRESENTATION_ID, request, sessionData, BASE64_KEY);

        // Then - should return internal server error
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
    }

    @Test
    public void testHandlePresentationAction_Submission_DecryptionException() throws Exception {
        // Given
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(Arrays.asList("cred-123"))
                .build();

        when(presentationSubmissionService.submitPresentation(
                any(), any(), any(), any(), any()))
                .thenThrow(new DecryptionException("Decryption failed", null));

        // When
        ResponseEntity<?> response = presentationActionService.handlePresentationAction(
                WALLET_ID, PRESENTATION_ID, request, sessionData, BASE64_KEY);

        // Then - should return internal server error
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
    }

    @Test
    public void testHandlePresentationAction_Submission_ApiNotAccessibleException() throws Exception {
        // Given
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(Arrays.asList("cred-123"))
                .build();

        when(presentationSubmissionService.submitPresentation(
                any(), any(), any(), any(), any()))
                .thenThrow(new ApiNotAccessibleException("API not accessible"));

        // When
        ResponseEntity<?> response = presentationActionService.handlePresentationAction(
                WALLET_ID, PRESENTATION_ID, request, sessionData, BASE64_KEY);

        // Then - should return internal server error
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
    }

    @Test
    public void testHandlePresentationAction_Submission_IOException() throws Exception {
        // Given
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(Arrays.asList("cred-123"))
                .build();

        when(presentationSubmissionService.submitPresentation(
                any(), any(), any(), any(), any()))
                .thenThrow(new IOException("IO error"));

        // When
        ResponseEntity<?> response = presentationActionService.handlePresentationAction(
                WALLET_ID, PRESENTATION_ID, request, sessionData, BASE64_KEY);

        // Then - should return internal server error
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
    }

    @Test
    public void testHandlePresentationAction_Rejection_VPErrorNotSentException() throws Exception {
        // Given
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .errorCode("access_denied")
                .errorMessage("User denied")
                .build();

        when(presentationService.rejectVerifier(any(), any(), any()))
                .thenThrow(new VPErrorNotSentException("Failed to send error to verifier"));

        // When
        ResponseEntity<?> response = presentationActionService.handlePresentationAction(
                WALLET_ID, PRESENTATION_ID, request, sessionData, BASE64_KEY);

        // Then - should return internal server error
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
    }

    @Test
    public void testHandlePresentationAction_RejectionWithNullWalletKey() {
        // Given - rejection doesn't need wallet key
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .errorCode("access_denied")
                .errorMessage("User denied authorization")
                .build();

        RejectedVerifierDTO expectedResponse = new RejectedVerifierDTO(
                "success",
                null,
                "Presentation request rejected."
        );

        when(presentationService.rejectVerifier(eq(WALLET_ID), eq(sessionData), any(ErrorDTO.class)))
                .thenReturn(expectedResponse);

        // When - wallet key is null but should still work for rejection
        ResponseEntity<?> response = presentationActionService.handlePresentationAction(
                WALLET_ID, PRESENTATION_ID, request, sessionData, null);

        // Then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        verify(presentationService, times(1)).rejectVerifier(any(), any(), any());
    }

    @Test
    public void testHandlePresentationAction_SubmissionWithMultipleCredentials() throws Exception {
        // Given
        SubmitPresentationRequestDTO request = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(Arrays.asList("cred-1", "cred-2", "cred-3", "cred-4"))
                .build();

        SubmitPresentationResponseDTO expectedResponse = SubmitPresentationResponseDTO.builder()
                .presentationId(PRESENTATION_ID)
                .status("SUCCESS")
                .message("Presentation successfully submitted")
                .build();

        when(presentationSubmissionService.submitPresentation(
                any(), any(), any(), any(), any()))
                .thenReturn(expectedResponse);

        // When
        ResponseEntity<?> response = presentationActionService.handlePresentationAction(
                WALLET_ID, PRESENTATION_ID, request, sessionData, BASE64_KEY);

        // Then
        assertEquals(HttpStatus.OK, response.getStatusCode());
        verify(presentationSubmissionService, times(1)).submitPresentation(
                eq(sessionData), eq(WALLET_ID), eq(PRESENTATION_ID), eq(request), eq(BASE64_KEY));
    }
}

