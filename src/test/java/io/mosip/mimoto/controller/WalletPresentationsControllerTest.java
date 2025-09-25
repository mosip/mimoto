package io.mosip.mimoto.controller;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.mosip.mimoto.dto.*;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.VPNotCreatedException;
import io.mosip.mimoto.service.PresentationService;
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
import io.mosip.mimoto.service.CredentialMatchingService;


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

}