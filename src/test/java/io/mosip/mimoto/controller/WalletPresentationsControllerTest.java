package io.mosip.mimoto.controller;

import io.mosip.mimoto.dto.*;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.DecryptionException;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.exception.KeyGenerationException;
import io.mosip.mimoto.exception.VPNotCreatedException;
import io.mosip.mimoto.service.CredentialMatchingService;
import io.mosip.mimoto.exception.VPErrorNotSentException;
import io.mosip.mimoto.service.PresentationService;
import io.mosip.mimoto.service.PresentationSubmissionService;
import io.mosip.mimoto.service.impl.SessionManager;
import io.mosip.mimoto.util.GlobalExceptionHandler;
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.io.IOException;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.doThrow;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = {WalletPresentationsController.class, GlobalExceptionHandler.class})
@AutoConfigureMockMvc(addFilters = false)
@EnableWebMvc
@Slf4j
public class WalletPresentationsControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private ObjectMapper objectMapper;

    @MockBean
    private PresentationService presentationService;

    @Mock
    private HttpSession httpSession;

    @MockBean
    private SessionManager sessionManager;

    @MockBean
    private CredentialMatchingService credentialMatchingService;

    @MockBean
    private PresentationSubmissionService presentationSubmissionService;

    private final String walletId = "wallet123";
    private final String walletKey = "encodedKey";

    private VerifiablePresentationResponseDTO presentationResponseDTO;

    @Before
    public void setup() {
        MockitoAnnotations.openMocks(this);
        VerifiablePresentationVerifierDTO presentationVerifierDTO = new VerifiablePresentationVerifierDTO("mock-client", "verifier123", "https://veriifer-logo.png", false, true, "https://verifier-redirect");
        presentationResponseDTO = new VerifiablePresentationResponseDTO("presentationId-123", presentationVerifierDTO);

        when(httpSession.getAttribute("wallet_id")).thenReturn(walletId);
        when(httpSession.getAttribute("wallet_key")).thenReturn(walletKey);
    }

    @Test
    public void testCreatePresentationSuccess() throws Exception {
        String authorizationRequestUrl = "client_id=mock-client&presentation_definition_uri=https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fpresentation_definition_uri&response_type=vp_token&response_mode=direct_post&nonce=NHgLcWlae745DpfJbUyfdg%253D%253D&response_uri=https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fvp-response&state=pcmxBfvdPEcjFObgt%252BLekA%253D%253D";
        VerifiablePresentationAuthorizationRequest authorizationRequest = new VerifiablePresentationAuthorizationRequest();
        authorizationRequest.setAuthorizationRequestUrl(authorizationRequestUrl);
        when(presentationService.handleVPAuthorizationRequest(authorizationRequest.getAuthorizationRequestUrl(), walletId)).thenReturn(presentationResponseDTO);
        String expectedResponse = new ObjectMapper().writeValueAsString(presentationResponseDTO);

        mockMvc.perform(post("/wallets/{walletId}/presentations", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(authorizationRequest))
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(result -> {
                    String actualResponse = result.getResponse().getContentAsString();
                    assertEquals(expectedResponse, actualResponse, "The response does not match the expected output");
                });
    }

    @Test
    public void shouldThrowExceptionWhenBadAuthorizationRequestIsReceivedFromVerifier() throws Exception {
        String authorizationRequestUrl = "presentation_definition_uri=https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fpresentation_definition_uri&response_type=vp_token&response_mode=direct_post&nonce=NHgLcWlae745DpfJbUyfdg%253D%253D&response_uri=https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fvp-response&state=pcmxBfvdPEcjFObgt%252BLekA%253D%253D";
        VerifiablePresentationAuthorizationRequest authorizationRequest = new VerifiablePresentationAuthorizationRequest();
        authorizationRequest.setAuthorizationRequestUrl(authorizationRequestUrl);
        when(presentationService.handleVPAuthorizationRequest(authorizationRequest.getAuthorizationRequestUrl(), walletId)).thenThrow(new OpenID4VPExceptions.MissingInput(List.of("client_id"), "client_id request param is Missing", "AuthorizationRequest"));

        mockMvc.perform(post("/wallets/{walletId}/presentations", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(authorizationRequest))
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value("Missing Input: client_id param is required"));
    }

    @Test
    public void shouldThrowSpecificErrorCodeAndMessageWhenAnyCustomExceptionIsThrown() throws Exception {
        String authorizationRequestUrl = "presentation_definition_uri=https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fpresentation_definition_uri&response_type=vp_token&response_mode=direct_post&nonce=NHgLcWlae745DpfJbUyfdg%253D%253D&response_uri=https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fvp-response&state=pcmxBfvdPEcjFObgt%252BLekA%253D%253D";
        VerifiablePresentationAuthorizationRequest authorizationRequest = new VerifiablePresentationAuthorizationRequest();
        authorizationRequest.setAuthorizationRequestUrl(authorizationRequestUrl);
        when(presentationService.handleVPAuthorizationRequest(authorizationRequest.getAuthorizationRequestUrl(), walletId)).thenThrow(new ApiNotAccessibleException("Error occurred while fetching trusted verifiers"));

        mockMvc.perform(post("/wallets/{walletId}/presentations", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(authorizationRequest))
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("RESIDENT-APP-026"))
                .andExpect(jsonPath("$.errorMessage").value("Error occurred while fetching trusted verifiers"));
    }

    @Test
    public void shouldThrowWalletCreateExceptionWhenAnyUnexpectedErrorOccurs() throws Exception {
        String authorizationRequestUrl = "presentation_definition_uri=https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fpresentation_definition_uri&response_type=vp_token&response_mode=direct_post&nonce=NHgLcWlae745DpfJbUyfdg%253D%253D&response_uri=https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fvp-response&state=pcmxBfvdPEcjFObgt%252BLekA%253D%253D";
        VerifiablePresentationAuthorizationRequest authorizationRequest = new VerifiablePresentationAuthorizationRequest();
        authorizationRequest.setAuthorizationRequestUrl(authorizationRequestUrl);
        when(presentationService.handleVPAuthorizationRequest(authorizationRequest.getAuthorizationRequestUrl(), walletId)).thenThrow(new RuntimeException("Error occurred while creating presentation in openid4vp flow"));

        mockMvc.perform(post("/wallets/{walletId}/presentations", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(authorizationRequest))
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("internal_server_error"))
                .andExpect(jsonPath("$.errorMessage").value("We are unable to process request now"));
    }

    @Test
    public void shouldThrowUnauthorizedWhenWalletKeyIsMissingFromSession() throws Exception {
        String presentationId = "presentation123";

        when(httpSession.getAttribute("wallet_key")).thenReturn(null);

        mockMvc.perform(get("/wallets/{walletId}/presentations/{presentationId}/credentials", walletId, presentationId)
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", walletId))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").value("unauthorized"))
                .andExpect(jsonPath("$.errorMessage").value("You are not authorized to access this resource"));
    }

    @Test
    public void shouldThrowBadRequestWhenApiNotAccessibleExceptionIsThrown() throws Exception {
        String presentationId = "presentation123";
        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(
                presentationId, "authorizationRequestUrl", java.time.Instant.now(), true, null);

        when(sessionManager.getPresentationSessionData(httpSession, walletId, presentationId)).thenReturn(sessionData);
        when(credentialMatchingService.getMatchingCredentials(sessionData, walletId, walletKey))
                .thenThrow(new ApiNotAccessibleException("Error occurred while fetching credentials"));

        mockMvc.perform(get("/wallets/{walletId}/presentations/{presentationId}/credentials", walletId, presentationId)
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("internal_server_error"))
                .andExpect(jsonPath("$.errorMessage").value("We are unable to process request now"));
    }

    @Test
    public void shouldThrowInternalServerErrorWhenIOExceptionIsThrown() throws Exception {
        String presentationId = "presentation123";
        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(
                presentationId, "authorizationRequestUrl", java.time.Instant.now(), true, null);

        when(sessionManager.getPresentationSessionData(httpSession, walletId, presentationId)).thenReturn(sessionData);
        when(credentialMatchingService.getMatchingCredentials(sessionData, walletId, walletKey))
                .thenThrow(new IOException("Error occurred while processing credentials"));

        mockMvc.perform(get("/wallets/{walletId}/presentations/{presentationId}/credentials", walletId, presentationId)
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("internal_server_error"))
                .andExpect(jsonPath("$.errorMessage").value("We are unable to process request now"));
    }

    @Test
    public void shouldThrowInternalServerErrorWhenVPNotCreatedExceptionIsThrown() throws Exception {
        String presentationId = "presentation123";
        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(
                presentationId, "authorizationRequestUrl", java.time.Instant.now(), true, null);

        when(sessionManager.getPresentationSessionData(httpSession, walletId, presentationId)).thenReturn(sessionData);
        when(credentialMatchingService.getMatchingCredentials(sessionData, walletId, walletKey))
                .thenThrow(new VPNotCreatedException("Error occurred while creating VP"));

        mockMvc.perform(get("/wallets/{walletId}/presentations/{presentationId}/credentials", walletId, presentationId)
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("internal_server_error"))
                .andExpect(jsonPath("$.errorMessage").value("We are unable to process request now"));
    }

    @Test
    public void shouldThrowInternalServerErrorWhenIllegalArgumentExceptionIsThrown() throws Exception {
        String presentationId = "presentation123";
        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(
                presentationId, "authorizationRequestUrl", java.time.Instant.now(), true, null);

        when(sessionManager.getPresentationSessionData(httpSession, walletId, presentationId)).thenReturn(sessionData);
        when(credentialMatchingService.getMatchingCredentials(sessionData, walletId, walletKey))
                .thenThrow(new IllegalArgumentException("Invalid argument provided"));

        mockMvc.perform(get("/wallets/{walletId}/presentations/{presentationId}/credentials", walletId, presentationId)
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("internal_server_error"))
                .andExpect(jsonPath("$.errorMessage").value("We are unable to process request now"));
    }

    @Test
    public void shouldThrowBadRequestWhenWalletIdInSessionIsNull() throws Exception {
        String presentationId = "presentation123";

        when(httpSession.getAttribute("wallet_id")).thenReturn(null);

        mockMvc.perform(get("/wallets/{walletId}/presentations/{presentationId}/credentials", walletId, presentationId)
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("wallet_locked"))
                .andExpect(jsonPath("$.errorMessage").value("Wallet is locked"));
    }

    @Test
    public void shouldThrowBadRequestWhenWalletIdInSessionDoesNotMatchRequest() throws Exception {
        String presentationId = "presentation123";
        String differentWalletId = "differentWallet123";

        when(httpSession.getAttribute("wallet_id")).thenReturn(differentWalletId);

        mockMvc.perform(get("/wallets/{walletId}/presentations/{presentationId}/credentials", walletId, presentationId)
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", differentWalletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value("Invalid Wallet ID. Session and request Wallet ID do not match"));
    }

    @Test
    public void shouldThrowInternalServerErrorWhenSessionDataIsNull() throws Exception {
        String presentationId = "presentation123";

        when(sessionManager.getPresentationSessionData(httpSession, walletId, presentationId)).thenReturn(null);

        mockMvc.perform(get("/wallets/{walletId}/presentations/{presentationId}/credentials", walletId, presentationId)
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("internal_server_error"))
                .andExpect(jsonPath("$.errorMessage").value("We are unable to process request now"));
    }

    @Test
    public void testUserRejectedVerifierSuccess() throws Exception {
        String presentationId = "presentation-123";

        // create a mock session data object (constructor signature may vary, so mock it)
        VerifiablePresentationSessionData sessionData = mock(VerifiablePresentationSessionData.class);

        // Mock the SessionManager to return the correct session data
        when(sessionManager.getPresentationSessionData(any(HttpSession.class), eq(walletId), eq(presentationId)))
                .thenReturn(sessionData);

        // Prepare the expected RejectedVerifierDTO and stub the service to return it
        RejectedVerifierDTO expectedRejected = new RejectedVerifierDTO("success", "", "Presentation request rejected. An OpenID4VP error response has been sent to the verifier.");
        when(presentationService.rejectVerifier(eq(walletId), eq(sessionData), any(ErrorDTO.class)))
                .thenReturn(expectedRejected);

        mockMvc.perform(patch("/wallets/{walletId}/presentations/{presentationId}", walletId, presentationId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"errorCode\":\"access_denied\",\"errorMessage\":\"User denied authorization\"}")
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("success"))
                .andExpect(jsonPath("$.message").value("Presentation request rejected. An OpenID4VP error response has been sent to the verifier."))
                .andExpect(jsonPath("$.redirectUri").value(""));
    }

    @Test
    public void testUserRejectedVerifierInvalidWalletId() throws Exception {
        String presentationId = "presentation-123";
        String invalidWalletId = "invalid-wallet";

        mockMvc.perform(patch("/wallets/{walletId}/presentations/{presentationId}", invalidWalletId, presentationId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"errorCode\":\"access_denied\",\"errorMessage\":\"User denied authorization\"}")
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isInternalServerError());

        verifyNoInteractions(presentationService);
    }

    @Test
    public void testUserRejectedVerifierServiceException() throws Exception {
        String presentationId = "presentation-123";

        VerifiablePresentationSessionData sessionData = mock(VerifiablePresentationSessionData.class);

        when(sessionManager.getPresentationSessionData(any(HttpSession.class), eq(walletId), eq(presentationId)))
                .thenReturn(sessionData);

        doThrow(new VPErrorNotSentException("Service error")).when(presentationService)
                .rejectVerifier(eq(walletId), eq(sessionData), any(ErrorDTO.class));

        mockMvc.perform(patch("/wallets/{walletId}/presentations/{presentationId}", walletId, presentationId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"errorCode\":\"access_denied\",\"errorMessage\":\"User denied authorization\"}")
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.message").value("Service error"));

        verify(sessionManager).getPresentationSessionData(any(HttpSession.class), eq(walletId), eq(presentationId));
        verify(presentationService).rejectVerifier(eq(walletId), eq(sessionData), any(ErrorDTO.class));
    }

    @Test
    public void testUserRejectedVerifierNullSessionData() throws Exception {
        String walletId = "wallet-123";
        String presentationId = "presentation-123";
        ErrorDTO payload = new ErrorDTO("access_denied", "User denied authorization");

        // Arrange: make session manager return null to simulate missing session data
        when(sessionManager.getPresentationSessionData(any(HttpSession.class), eq(walletId), eq(presentationId)))
                .thenReturn(null);

        // Serialize payload to ensure MockMvc .content(...) is not null
        String content = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(payload);

        mockMvc.perform(patch("/wallets/{walletId}/presentations/{presentationId}", walletId, presentationId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(content)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest());
    }

    @Test
    public void testUserRejectedVerifierInvalidRequestExceptionFromService() throws Exception {
        String presentationId = "presentation-123";

        VerifiablePresentationSessionData sessionData = mock(VerifiablePresentationSessionData.class);

        when(sessionManager.getPresentationSessionData(any(HttpSession.class), eq(walletId), eq(presentationId)))
                .thenReturn(sessionData);

        doThrow(new InvalidRequestException("invalid_request", "Invalid payload")).when(presentationService)
                .rejectVerifier(eq(walletId), eq(sessionData), any(ErrorDTO.class));

        mockMvc.perform(patch("/wallets/{walletId}/presentations/{presentationId}", walletId, presentationId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"errorCode\":\"access_denied\",\"errorMessage\":\"User denied authorization\"}")
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isInternalServerError());

        verify(presentationService).rejectVerifier(eq(walletId), eq(sessionData), any(ErrorDTO.class));
    }

    @Test
    public void testHandleVPAuthorizationRequestWithURISyntaxException() throws Exception {
        String authorizationRequestUrl = "invalid://url with spaces";
        VerifiablePresentationAuthorizationRequest authorizationRequest = new VerifiablePresentationAuthorizationRequest();
        authorizationRequest.setAuthorizationRequestUrl(authorizationRequestUrl);
        
        when(presentationService.handleVPAuthorizationRequest(authorizationRequestUrl, walletId))
                .thenThrow(new java.net.URISyntaxException("invalid://url with spaces", "Invalid URI"));

        mockMvc.perform(post("/wallets/{walletId}/presentations", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(authorizationRequest))
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"));
    }

    @Test
    public void testHandleVPAuthorizationRequestWithVPNotCreatedException() throws Exception {
        String authorizationRequestUrl = "client_id=test&response_type=vp_token";
        VerifiablePresentationAuthorizationRequest authorizationRequest = new VerifiablePresentationAuthorizationRequest();
        authorizationRequest.setAuthorizationRequestUrl(authorizationRequestUrl);
        
        when(presentationService.handleVPAuthorizationRequest(authorizationRequestUrl, walletId))
                .thenThrow(new VPNotCreatedException("Failed to create VP"));

        mockMvc.perform(post("/wallets/{walletId}/presentations", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(authorizationRequest))
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"));
    }

    @Test
    public void testGetMatchingCredentialsSuccess() throws Exception {
        String presentationId = "presentation-123";
        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(
                presentationId, "authorizationRequestUrl", java.time.Instant.now(), true, null);

        MatchingCredentialsResponseDTO responseDTO = new MatchingCredentialsResponseDTO();
        MatchingCredentialsWithWalletDataDTO matchingCredentials = new MatchingCredentialsWithWalletDataDTO();
        matchingCredentials.setMatchingCredentialsResponse(responseDTO);
        matchingCredentials.setMatchingCredentials(java.util.Collections.emptyList());

        when(sessionManager.getPresentationSessionData(any(HttpSession.class), eq(walletId), eq(presentationId))).thenReturn(sessionData);
        when(credentialMatchingService.getMatchingCredentials(sessionData, walletId, walletKey))
                .thenReturn(matchingCredentials);

        mockMvc.perform(get("/wallets/{walletId}/presentations/{presentationId}/credentials", walletId, presentationId)
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isOk());

        verify(sessionManager).storeMatchingWalletCredentialsInPresentationSessionData(
                any(HttpSession.class), eq(walletId), eq(sessionData), anyList());
    }

    @Test
    public void testGetMatchingCredentialsWithIllegalArgumentException() throws Exception {
        String presentationId = "presentation-123";
        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(
                presentationId, "authorizationRequestUrl", java.time.Instant.now(), true, null);

        when(sessionManager.getPresentationSessionData(any(HttpSession.class), eq(walletId), eq(presentationId))).thenReturn(sessionData);
        when(credentialMatchingService.getMatchingCredentials(sessionData, walletId, walletKey))
                .thenThrow(new IllegalArgumentException("Invalid argument"));

        mockMvc.perform(get("/wallets/{walletId}/presentations/{presentationId}/credentials", walletId, presentationId)
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").exists());
    }

    @Test
    public void testHandlePresentationSubmissionSuccess() throws Exception {
        String presentationId = "presentation-123";
        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(
                presentationId, "authorizationRequestUrl", java.time.Instant.now(), true, null);

        SubmitPresentationRequestDTO submitRequest = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(java.util.Arrays.asList("cred-1", "cred-2"))
                .build();

        SubmitPresentationResponseDTO submitResponse = new SubmitPresentationResponseDTO();
        submitResponse.setStatus("SUCCESS");
        submitResponse.setPresentationId(presentationId);

        when(sessionManager.getPresentationSessionData(any(HttpSession.class), eq(walletId), eq(presentationId)))
                .thenReturn(sessionData);
        when(presentationSubmissionService.submitPresentation(
                eq(sessionData), eq(walletId), eq(presentationId), any(SubmitPresentationRequestDTO.class), eq(walletKey)))
                .thenReturn(submitResponse);

        mockMvc.perform(patch("/wallets/{walletId}/presentations/{presentationId}", walletId, presentationId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(submitRequest))
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("SUCCESS"))
                .andExpect(jsonPath("$.presentationId").value(presentationId));

        verify(presentationSubmissionService).submitPresentation(
                eq(sessionData), eq(walletId), eq(presentationId), any(SubmitPresentationRequestDTO.class), eq(walletKey));
    }

    @Test
    public void testHandlePresentationSubmissionWithJOSEException() throws Exception {
        String presentationId = "presentation-123";
        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(
                presentationId, "authorizationRequestUrl", java.time.Instant.now(), true, null);

        SubmitPresentationRequestDTO submitRequest = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(java.util.Arrays.asList("cred-1"))
                .build();

        when(sessionManager.getPresentationSessionData(any(HttpSession.class), eq(walletId), eq(presentationId)))
                .thenReturn(sessionData);
        when(presentationSubmissionService.submitPresentation(
                eq(sessionData), eq(walletId), eq(presentationId), any(SubmitPresentationRequestDTO.class), eq(walletKey)))
                .thenThrow(new com.nimbusds.jose.JOSEException("JWT signing failed"));

        mockMvc.perform(patch("/wallets/{walletId}/presentations/{presentationId}", walletId, presentationId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(submitRequest))
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("JWT_SIGNING_ERROR"));
    }

    @Test
    public void testHandlePresentationSubmissionWithKeyGenerationException() throws Exception {
        String presentationId = "presentation-123";
        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(
                presentationId, "authorizationRequestUrl", java.time.Instant.now(), true, null);

        SubmitPresentationRequestDTO submitRequest = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(java.util.Arrays.asList("cred-1"))
                .build();

        when(sessionManager.getPresentationSessionData(any(HttpSession.class), eq(walletId), eq(presentationId)))
                .thenReturn(sessionData);
        when(presentationSubmissionService.submitPresentation(
                eq(sessionData), eq(walletId), eq(presentationId), any(SubmitPresentationRequestDTO.class), eq(walletKey)))
                .thenThrow(new KeyGenerationException("KEY_ERROR", "Failed to generate key"));

        mockMvc.perform(patch("/wallets/{walletId}/presentations/{presentationId}", walletId, presentationId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(submitRequest))
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").exists());
    }

    @Test
    public void testHandlePresentationSubmissionWithDecryptionException() throws Exception {
        String presentationId = "presentation-123";
        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(
                presentationId, "authorizationRequestUrl", java.time.Instant.now(), true, null);

        SubmitPresentationRequestDTO submitRequest = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(java.util.Arrays.asList("cred-1"))
                .build();

        when(sessionManager.getPresentationSessionData(any(HttpSession.class), eq(walletId), eq(presentationId)))
                .thenReturn(sessionData);
        when(presentationSubmissionService.submitPresentation(
                eq(sessionData), eq(walletId), eq(presentationId), any(SubmitPresentationRequestDTO.class), eq(walletKey)))
                .thenThrow(new DecryptionException("DECRYPT_ERROR", "Failed to decrypt"));

        mockMvc.perform(patch("/wallets/{walletId}/presentations/{presentationId}", walletId, presentationId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(submitRequest))
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").exists());
    }

    @Test
    public void testHandlePresentationSubmissionWithApiNotAccessibleException() throws Exception {
        String presentationId = "presentation-123";
        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(
                presentationId, "authorizationRequestUrl", java.time.Instant.now(), true, null);

        SubmitPresentationRequestDTO submitRequest = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(java.util.Arrays.asList("cred-1"))
                .build();

        when(sessionManager.getPresentationSessionData(any(HttpSession.class), eq(walletId), eq(presentationId)))
                .thenReturn(sessionData);
        when(presentationSubmissionService.submitPresentation(
                eq(sessionData), eq(walletId), eq(presentationId), any(SubmitPresentationRequestDTO.class), eq(walletKey)))
                .thenThrow(new ApiNotAccessibleException("API error"));

        mockMvc.perform(patch("/wallets/{walletId}/presentations/{presentationId}", walletId, presentationId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(submitRequest))
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").exists());
    }

    @Test
    public void testHandlePresentationSubmissionWithIOException() throws Exception {
        String presentationId = "presentation-123";
        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(
                presentationId, "authorizationRequestUrl", java.time.Instant.now(), true, null);

        SubmitPresentationRequestDTO submitRequest = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(java.util.Arrays.asList("cred-1"))
                .build();

        when(sessionManager.getPresentationSessionData(any(HttpSession.class), eq(walletId), eq(presentationId)))
                .thenReturn(sessionData);
        when(presentationSubmissionService.submitPresentation(
                eq(sessionData), eq(walletId), eq(presentationId), any(SubmitPresentationRequestDTO.class), eq(walletKey)))
                .thenThrow(new IOException("IO error"));

        mockMvc.perform(patch("/wallets/{walletId}/presentations/{presentationId}", walletId, presentationId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(submitRequest))
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").exists());
    }

    @Test
    public void testHandlePresentationSubmissionWithIllegalArgumentException() throws Exception {
        String presentationId = "presentation-123";
        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(
                presentationId, "authorizationRequestUrl", java.time.Instant.now(), true, null);

        SubmitPresentationRequestDTO submitRequest = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(java.util.Arrays.asList("cred-1"))
                .build();

        when(sessionManager.getPresentationSessionData(any(HttpSession.class), eq(walletId), eq(presentationId)))
                .thenReturn(sessionData);
        when(presentationSubmissionService.submitPresentation(
                eq(sessionData), eq(walletId), eq(presentationId), any(SubmitPresentationRequestDTO.class), eq(walletKey)))
                .thenThrow(new IllegalArgumentException("Invalid argument"));

        mockMvc.perform(patch("/wallets/{walletId}/presentations/{presentationId}", walletId, presentationId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(submitRequest))
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").exists());
    }

    @Test
    public void testHandlePresentationSubmissionMissingWalletKey() throws Exception {
        String presentationId = "presentation-123";
        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(
                presentationId, "authorizationRequestUrl", java.time.Instant.now(), true, null);

        SubmitPresentationRequestDTO submitRequest = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(java.util.Arrays.asList("cred-1"))
                .build();

        when(httpSession.getAttribute("wallet_key")).thenReturn(null);
        when(sessionManager.getPresentationSessionData(any(HttpSession.class), eq(walletId), eq(presentationId)))
                .thenReturn(sessionData);

        mockMvc.perform(patch("/wallets/{walletId}/presentations/{presentationId}", walletId, presentationId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(submitRequest))
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", walletId))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.errorCode").value("unauthorized"));
    }

    @Test
    public void testHandlePresentationActionInvalidRequestFormat() throws Exception {
        String presentationId = "presentation-123";
        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(
                presentationId, "authorizationRequestUrl", java.time.Instant.now(), true, null);

        SubmitPresentationRequestDTO invalidRequest = SubmitPresentationRequestDTO.builder()
                .build();

        when(sessionManager.getPresentationSessionData(any(HttpSession.class), eq(walletId), eq(presentationId)))
                .thenReturn(sessionData);

        mockMvc.perform(patch("/wallets/{walletId}/presentations/{presentationId}", walletId, presentationId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(invalidRequest))
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest());
    }

    @Test
    public void testGetErrorResponseEntityWithDelimiter() throws Exception {
        String presentationId = "presentation-123";
        VerifiablePresentationSessionData sessionData = new VerifiablePresentationSessionData(
                presentationId, "authorizationRequestUrl", java.time.Instant.now(), true, null);

        when(sessionManager.getPresentationSessionData(any(HttpSession.class), eq(walletId), eq(presentationId)))
                .thenReturn(sessionData);
        
        VPErrorNotSentException exceptionWithDelimiter = new VPErrorNotSentException("custom_error_code-->Custom error message");
        doThrow(exceptionWithDelimiter).when(presentationService)
                .rejectVerifier(eq(walletId), eq(sessionData), any(ErrorDTO.class));

        mockMvc.perform(patch("/wallets/{walletId}/presentations/{presentationId}", walletId, presentationId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"errorCode\":\"access_denied\",\"errorMessage\":\"User denied\"}")
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isInternalServerError());
    }


}