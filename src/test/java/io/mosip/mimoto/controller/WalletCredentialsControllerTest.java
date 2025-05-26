package io.mosip.mimoto.controller;

import io.mosip.mimoto.dto.VerifiableCredentialRequestDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.VerifiableCredentialResponseDTO;
import io.mosip.mimoto.dto.resident.WalletCredentialResponseDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.CredentialNotFoundException;
import io.mosip.mimoto.exception.CredentialProcessingException;
import io.mosip.mimoto.exception.ExternalServiceUnavailableException;
import io.mosip.mimoto.service.WalletCredentialService;
import io.mosip.mimoto.util.CredentialUtilService;
import io.mosip.mimoto.util.GlobalExceptionHandler;
import jakarta.servlet.http.HttpSession;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.io.ByteArrayInputStream;
import java.util.Collections;
import java.util.List;

import static io.mosip.mimoto.exception.ErrorConstants.CREDENTIAL_FETCH_EXCEPTION;
import static io.mosip.mimoto.exception.ErrorConstants.RESOURCE_NOT_FOUND;
import static io.mosip.mimoto.util.TestUtilities.createRequestBody;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = {WalletCredentialsController.class, GlobalExceptionHandler.class})
@AutoConfigureMockMvc(addFilters = false)
@EnableWebMvc
public class WalletCredentialsControllerTest {

    @InjectMocks
    private WalletCredentialsController controller;

    @MockBean
    private WalletCredentialService walletCredentialService;

    @MockBean
    private CredentialUtilService credentialUtilService;

    @Mock
    private HttpSession httpSession;

    @Autowired
    private MockMvc mockMvc;

    private VerifiableCredentialResponseDTO verifiableCredentialResponseDTO;
    private WalletCredentialResponseDTO walletCredentialResponseDTO;
    private final String walletId = "wallet123";
    private final String credentialId = "cred456";
    private final String walletKey = "encodedKey";
    private final String issuer = "issuer1";
    private final String credentialConfigurationId = "type1";
    private final String locale = "en";
    VerifiableCredentialRequestDTO verifiableCredentialRequest;

    @Before
    public void setup() {
        MockitoAnnotations.openMocks(this);
        verifiableCredentialRequest = new VerifiableCredentialRequestDTO();

        verifiableCredentialResponseDTO = VerifiableCredentialResponseDTO.builder()
                .issuerDisplayName("issuerName123")
                .issuerLogo("issuerLogo")
                .credentialTypeDisplayName("credentialType123")
                .credentialTypeLogo("credentialTypeLogo")
                .credentialId("credentialId123")
                .build();

        walletCredentialResponseDTO = new WalletCredentialResponseDTO();
        walletCredentialResponseDTO.setFileName("credential.pdf");
        walletCredentialResponseDTO.setFileContentStream(new InputStreamResource(new ByteArrayInputStream("test-pdf".getBytes())));

        when(httpSession.getAttribute("wallet_id")).thenReturn(walletId);
        when(httpSession.getAttribute("wallet_key")).thenReturn(walletKey);
    }

    // Tests for downloadCredential
    @Test
    public void shouldDownloadCredentialSuccessfully() throws Exception {
        setIssuerAndCredentialConfigurationId(issuer, credentialConfigurationId);
        when(credentialUtilService.getTokenResponse(eq(verifiableCredentialRequest), eq(issuer))).thenReturn(new TokenResponseDTO());
        when(walletCredentialService.fetchAndStoreCredential(eq(issuer), eq(credentialConfigurationId), any(), eq(locale), eq(walletId), eq(walletKey)))
                .thenReturn(verifiableCredentialResponseDTO);

        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("Accept-Language", locale)
                        .content(createRequestBody(verifiableCredentialRequest))
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuerDisplayName").value("issuerName123"))
                .andExpect(jsonPath("$.issuerLogo").value("issuerLogo"))
                .andExpect(jsonPath("$.credentialTypeDisplayName").value("credentialType123"))
                .andExpect(jsonPath("$.credentialTypeLogo").value("credentialTypeLogo"))
                .andExpect(jsonPath("$.credentialId").value("credentialId123"));
    }

    @Test
    public void shouldReturnErrorResponseWhenSessionDoesNotHaveWalletIdAndKey() throws Exception {
        setIssuerAndCredentialConfigurationId(issuer, credentialConfigurationId);
        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("Accept-Language", locale)
                        .content(createRequestBody(verifiableCredentialRequest))
                )
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("wallet_locked"))
                .andExpect(jsonPath("$.errorMessage").value("wallet_locked --> Wallet is locked"));
    }

    @Test
    public void shouldCallServiceWithCorrectParameters() throws Exception {
        setIssuerAndCredentialConfigurationId(issuer, credentialConfigurationId);
        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .header("Accept-Language", "fr")
                .content(createRequestBody(verifiableCredentialRequest))
                .sessionAttr("wallet_id", walletId)
                .sessionAttr("wallet_key", walletKey));

        verify(credentialUtilService).getTokenResponse(eq(verifiableCredentialRequest), eq(issuer));
        verify(walletCredentialService
        ).fetchAndStoreCredential(eq(issuer), eq(credentialConfigurationId), any(), eq("fr"), eq(walletId), eq(walletKey));
    }

    @Test
    public void shouldSetDefaultAndProceedWhenOptionalRequestParametersAreNotPassed() throws Exception {
        setIssuerAndCredentialConfigurationId(issuer, credentialConfigurationId);
        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                .contentType(MediaType.APPLICATION_JSON)
                .accept(MediaType.APPLICATION_JSON)
                .content(createRequestBody(verifiableCredentialRequest))
                .sessionAttr("wallet_id", walletId)
                .sessionAttr("wallet_key", walletKey));

        // Default value for vcStorageExpiryLimit is -1 and locale is "en"
        verify(walletCredentialService).fetchAndStoreCredential(any(), any(), any(), eq("en"), eq(walletId), eq(walletKey));
    }

    @Test
    public void shouldThrowExceptionWhenInvalidLocaleIsPassed() throws Exception {
        setIssuerAndCredentialConfigurationId(issuer, credentialConfigurationId);

        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("Accept-Language", "eng") // Three letter language code passed which is not valid
                        .header("Accept-Language", "invalid")
                        .content(createRequestBody(verifiableCredentialRequest))
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value("Locale must be a 2-letter code"));
    }

    @Test
    public void shouldThrowInvalidRequestForWalletIdMismatch() throws Exception {
        when(httpSession.getAttribute("wallet_id")).thenReturn("differentWalletId");
        setIssuerAndCredentialConfigurationId(issuer, credentialConfigurationId);

        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(createRequestBody(verifiableCredentialRequest))
                        .sessionAttr("wallet_id", "differentWalletId")
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value("invalid_request --> Invalid Wallet ID. Session and request Wallet ID do not match"));
    }

    @Test
    public void shouldThrowInvalidRequestForMissingWalletKey() throws Exception {
        when(httpSession.getAttribute("wallet_key")).thenReturn(null);
        setIssuerAndCredentialConfigurationId(issuer, credentialConfigurationId);

        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(createRequestBody(verifiableCredentialRequest))
                        .sessionAttr("wallet_id", walletId))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value("invalid_request --> Wallet key not found in session"));
    }

    @Test
    public void shouldThrowInvalidRequestForMissingIssuerAndCredentialConfigurationId() throws Exception {
        setIssuerAndCredentialConfigurationId(null, null);
        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("Accept-Language", "fr")
                        .content(createRequestBody(verifiableCredentialRequest))
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value("Missing required parameters: issuerId, Missing required parameters: credentialConfigurationId"));
    }

    @Test
    public void shouldThrowInvalidRequestForMissingCredentialConfigurationId() throws Exception {
        setIssuerAndCredentialConfigurationId(issuer, null);
        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(createRequestBody(verifiableCredentialRequest))
                        .header("Accept-Language", "fr")
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value("Missing required parameters: credentialConfigurationId"));
    }

    @Test
    public void shouldThrowServiceUnavailableForTokenResponseFailure() throws Exception {
        setIssuerAndCredentialConfigurationId(issuer, credentialConfigurationId);
        when(credentialUtilService.getTokenResponse(eq(verifiableCredentialRequest), eq(issuer)))
                .thenThrow(new ApiNotAccessibleException("API not accessible"));

        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(createRequestBody(verifiableCredentialRequest))
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.errorCode").value("credential_download_error"));
    }

    @Test
    public void shouldThrowServiceUnavailableForExternalServiceFailure() throws Exception {
        setIssuerAndCredentialConfigurationId(issuer, credentialConfigurationId);
        when(credentialUtilService.getTokenResponse(anyMap(), eq(issuer))).thenReturn(new TokenResponseDTO());
        when(walletCredentialService.fetchAndStoreCredential(anyString(), anyString(), any(), anyString(), anyString(), anyString()))
                .thenThrow(new ExternalServiceUnavailableException("Service unavailable", "Service unavailable"));

        mockMvc.perform(post("/wallets/{walletId}/credentials", walletId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(createRequestBody(verifiableCredentialRequest))
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.errorCode").value("Service unavailable"))
                .andExpect(jsonPath("$.errorMessage").value("Service unavailable"));
    }

    // Tests for fetchAllCredentialsForGivenWallet

    @Test
    public void shouldFetchAllCredentialsSuccessfully() throws Exception {
        List<VerifiableCredentialResponseDTO> credentials = Collections.singletonList(verifiableCredentialResponseDTO);
        when(walletCredentialService.fetchAllCredentialsForWallet(walletId, walletKey, locale)).thenReturn(credentials);

        mockMvc.perform(get("/wallets/{walletId}/credentials", walletId)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("Accept-Language", locale)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].issuerDisplayName").value("issuerName123"))
                .andExpect(jsonPath("$[0].issuerLogo").value("issuerLogo"))
                .andExpect(jsonPath("$[0].credentialTypeDisplayName").value("credentialType123"))
                .andExpect(jsonPath("$[0].credentialId").value("credentialId123"))
                .andExpect(jsonPath("$[0].credentialTypeLogo").value("credentialTypeLogo"));
    }

    @Test
    public void shouldThrowInvalidRequestForInvalidLocale() throws Exception {
        mockMvc.perform(get("/wallets/{walletId}/credentials", walletId)
                        .header("Accept-Language", "invalid")
                        .param("issuer", issuer)
                        .param("credentialConfigurationId", credentialConfigurationId)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest());
    }

    @Test
    public void shouldThrowInvalidRequestForMissingWalletKeyInFetchAll() throws Exception {
        when(httpSession.getAttribute("wallet_key")).thenReturn(null);

        mockMvc.perform(get("/wallets/{walletId}/credentials", walletId)
                        .header("Accept-Language", locale)
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", walletId))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value("invalid_request --> Wallet key not found in session"));
    }

    @Test
    public void shouldThrowInvalidRequestForWalletIdMismatchInFetchAll() throws Exception {
        when(httpSession.getAttribute("wallet_id")).thenReturn("differentWalletId");

        mockMvc.perform(get("/wallets/{walletId}/credentials", walletId)
                        .header("Accept-Language", locale)
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", "differentWalletId")
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value("invalid_request --> Invalid Wallet ID. Session and request Wallet ID do not match"));
    }

    // Tests for getVerifiableCredential
    @Test
    public void shouldFetchVerifiableCredentialAsPdfSuccessfullyInline() throws Exception {
        when(walletCredentialService.fetchVerifiableCredential(walletId, credentialId, walletKey, locale))
                .thenReturn(walletCredentialResponseDTO);

        mockMvc.perform(get("/wallets/{walletId}/credentials/{credentialId}", walletId, credentialId)
                        .accept(MediaType.APPLICATION_PDF)
                        .header("Accept-Language", locale)
                        .param("action", "inline")
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition", "inline; filename=\"credential.pdf\""))
                .andExpect(content().contentType(MediaType.APPLICATION_PDF));
    }

    @Test
    public void shouldFetchVerifiableCredentialAsDownload() throws Exception {
        when(walletCredentialService.fetchVerifiableCredential(walletId, credentialId, walletKey, locale))
                .thenReturn(walletCredentialResponseDTO);

        mockMvc.perform(get("/wallets/{walletId}/credentials/{credentialId}", walletId, credentialId)
                        .accept(MediaType.APPLICATION_PDF)
                        .header("Accept-Language", locale)
                        .param("action", "download")
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition", "attachment; filename=\"credential.pdf\""))
                .andExpect(content().contentType(MediaType.APPLICATION_PDF));
    }

    @Test
    public void shouldThrowInvalidRequestForInvalidAcceptHeader() throws Exception {
        mockMvc.perform(get("/wallets/{walletId}/credentials/{credentialId}", walletId, credentialId)
                        .header("Accept-Language", locale)
                        .param("Accept", "application/json")
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value("Accept header must be application/pdf"));
    }

    @Test
    public void shouldThrowInvalidRequestForInvalidAction() throws Exception {
        mockMvc.perform(get("/wallets/{walletId}/credentials/{credentialId}", walletId, credentialId)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("Accept-Language", locale)
                        .param("action", "invalid")
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest());
    }

    @Test
    public void shouldThrowCredentialNotFoundException() throws Exception {
        when(walletCredentialService.fetchVerifiableCredential(walletId, credentialId, walletKey, locale))
                .thenThrow(new CredentialNotFoundException(RESOURCE_NOT_FOUND.getErrorCode(), RESOURCE_NOT_FOUND.getErrorMessage()));

        mockMvc.perform(get("/wallets/{walletId}/credentials/{credentialId}", walletId, credentialId)
                        .accept(MediaType.APPLICATION_PDF)
                        .header("Accept-Language", locale)
                        .param("action", "inline")
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.errorCode").value("resource_not_found"))
                .andExpect(jsonPath("$.errorMessage").value("The requested resource doesn’t exist."));
    }

    @Test
    public void shouldThrowInvalidRequestForMissingCredentialId() throws Exception {
        mockMvc.perform(get("/wallets/{walletId}/credentials/{credentialId}", walletId, ""))
                .andExpect(status().isNotFound());
    }

    @Test
    public void shouldThrowCredentialProcessingExceptionForDecryptionError() throws Exception {
        when(walletCredentialService.fetchVerifiableCredential(walletId, credentialId, walletKey, locale))
                .thenThrow(new CredentialProcessingException(CREDENTIAL_FETCH_EXCEPTION.getErrorCode(), "Decryption failed"));

        mockMvc.perform(get("/wallets/{walletId}/credentials/{credentialId}", walletId, credentialId)
                        .accept(MediaType.APPLICATION_PDF)
                        .header("Accept-Language", locale)
                        .param("action", "inline")
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("credential_fetch_error"))
                .andExpect(jsonPath("$.errorMessage").value("Decryption failed"));
    }

    @Test
    public void shouldThrowCredentialProcessingExceptionForCorruptedData() throws Exception {
        when(walletCredentialService.fetchVerifiableCredential(walletId, credentialId, walletKey, locale))
                .thenThrow(new CredentialProcessingException(CREDENTIAL_FETCH_EXCEPTION.getErrorCode(), "CORRUPTED_DATA"));

        mockMvc.perform(get("/wallets/{walletId}/credentials/{credentialId}", walletId, credentialId)
                        .accept(MediaType.APPLICATION_PDF)
                        .header("Accept-Language", locale)
                        .param("action", "inline")
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value(CREDENTIAL_FETCH_EXCEPTION.getErrorCode()))
                .andExpect(jsonPath("$.errorMessage").value("CORRUPTED_DATA"));
    }

    // Tests for deleteCredential
    @Test
    public void shouldDeleteCredentialSuccessfully() throws Exception {
        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete("/wallets/{walletId}/credentials/{credentialId}", walletId, credentialId)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isOk());
    }

    @Test
    public void shouldThrowCredentialNotFoundExceptionWhenDeletingNonExistentCredential() throws Exception {
        doThrow(new CredentialNotFoundException(RESOURCE_NOT_FOUND.getErrorCode(), RESOURCE_NOT_FOUND.getErrorMessage()))
                .when(walletCredentialService).deleteCredential(credentialId, walletId);

        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete("/wallets/{walletId}/credentials/{credentialId}", walletId, credentialId)
                        .sessionAttr("wallet_id", walletId)
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.errorCode").value("resource_not_found"))
                .andExpect(jsonPath("$.errorMessage").value("The requested resource doesn’t exist."));
    }

    @Test
    public void shouldThrowInvalidRequestForWalletIdMismatchInDeleteCredential() throws Exception {
        when(httpSession.getAttribute("wallet_id")).thenReturn("differentWalletId");

        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete("/wallets/{walletId}/credentials/{credentialId}", walletId, credentialId)
                        .sessionAttr("wallet_id", "differentWalletId")
                        .sessionAttr("wallet_key", walletKey))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value("Invalid Wallet ID. Session and request Wallet ID do not match"));
    }

    private void setIssuerAndCredentialConfigurationId(String issuer, String credentialConfigurationId) {
        verifiableCredentialRequest.setIssuer(issuer);
        verifiableCredentialRequest.setCredentialConfigurationId(credentialConfigurationId);
    }
}