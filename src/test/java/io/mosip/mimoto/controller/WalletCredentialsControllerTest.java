package io.mosip.mimoto.controller;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.VerifiableCredentialResponseDTO;
import io.mosip.mimoto.dto.resident.WalletCredentialResponseDTO;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.service.WalletCredentialService;
import io.mosip.mimoto.util.CredentialUtilService;
import jakarta.servlet.http.HttpSession;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class WalletCredentialsControllerTest {

    @InjectMocks
    private WalletCredentialsController walletCredentialsController;

    @Mock
    private WalletCredentialService walletCredentialService;

    @Mock
    private CredentialUtilService credentialUtilService;

    @Mock
    private HttpSession httpSession;

    private static final String WALLET_ID = "wallet123";
    private static final String CREDENTIAL_ID = "cred456";
    private static final String BASE64_ENCODED_WALLET_KEY = "encodedKey";
    private static final String ISSUER_ID = "issuer1";
    private static final String CREDENTIAL_TYPE = "type1";
    private static final String LOCALE = "en";
    private static final String VC_STORAGE_EXPIRY = "-1";

    @Before
    public void setUp() {
        when(httpSession.getAttribute(SessionKeys.WALLET_ID)).thenReturn(WALLET_ID);
        when(httpSession.getAttribute(SessionKeys.WALLET_KEY)).thenReturn(BASE64_ENCODED_WALLET_KEY);
    }

    @Test
    public void downloadCredentialSuccess() throws Exception {
        Map<String, String> params = new HashMap<>();
        params.put("issuer", ISSUER_ID);
        params.put("credential", CREDENTIAL_TYPE);
        params.put("locale", LOCALE);
        params.put("vcStorageExpiryLimitInTimes", VC_STORAGE_EXPIRY);

        TokenResponseDTO tokenResponse = new TokenResponseDTO();
        VerifiableCredentialResponseDTO responseDTO = new VerifiableCredentialResponseDTO();

        when(credentialUtilService.getTokenResponse(params, ISSUER_ID)).thenReturn(tokenResponse);
        when(walletCredentialService.fetchAndStoreCredential(eq(ISSUER_ID), eq(CREDENTIAL_TYPE), eq(tokenResponse),
                eq(VC_STORAGE_EXPIRY), eq(LOCALE), eq(WALLET_ID), eq(BASE64_ENCODED_WALLET_KEY)))
                .thenReturn(responseDTO);

        ResponseEntity<VerifiableCredentialResponseDTO> response = walletCredentialsController
                .downloadCredential(WALLET_ID, params, httpSession);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(responseDTO, response.getBody());
        verify(httpSession).getAttribute(SessionKeys.WALLET_ID);
        verify(httpSession).getAttribute(SessionKeys.WALLET_KEY);
        verify(credentialUtilService).getTokenResponse(params, ISSUER_ID);
        verify(walletCredentialService).fetchAndStoreCredential(eq(ISSUER_ID), eq(CREDENTIAL_TYPE), eq(tokenResponse),
                eq(VC_STORAGE_EXPIRY), eq(LOCALE), eq(WALLET_ID), eq(BASE64_ENCODED_WALLET_KEY));
    }

    @Test
    public void downloadCredentialInvalidWalletIdThrowsInvalidRequestException() {
        when(httpSession.getAttribute(SessionKeys.WALLET_ID)).thenReturn("differentWalletId");

        Map<String, String> params = new HashMap<>();
        params.put("issuer", ISSUER_ID);
        params.put("credential", CREDENTIAL_TYPE);

        try {
            walletCredentialsController.downloadCredential(WALLET_ID, params, httpSession);
            fail("Expected InvalidRequestException");
        } catch (InvalidRequestException e) {
            assertEquals(ErrorConstants.INVALID_REQUEST.getErrorCode(), e.getErrorCode());
            assertEquals("invalid_request --> Wallet ID mismatch", e.getMessage());
        }
        verify(httpSession).getAttribute(SessionKeys.WALLET_ID);
        verifyNoMoreInteractions(credentialUtilService, walletCredentialService);
    }

    @Test
    public void downloadCredentialMissingWalletKeyThrowsInvalidRequestException() {
        when(httpSession.getAttribute(SessionKeys.WALLET_KEY)).thenReturn(null);

        Map<String, String> params = new HashMap<>();
        params.put("issuer", ISSUER_ID);
        params.put("credential", CREDENTIAL_TYPE);

        try {
            walletCredentialsController.downloadCredential(WALLET_ID, params, httpSession);
            fail("Expected InvalidRequestException");
        } catch (InvalidRequestException e) {
            assertEquals(ErrorConstants.INVALID_REQUEST.getErrorCode(), e.getErrorCode());
            assertEquals("invalid_request --> Wallet key not found in session", e.getMessage());
        }
        verify(httpSession).getAttribute(SessionKeys.WALLET_ID);
        verify(httpSession).getAttribute(SessionKeys.WALLET_KEY);
        verifyNoInteractions(credentialUtilService, walletCredentialService);
    }

    @Test
    public void downloadCredentialMissingIssuerThrowsInvalidRequestException() {
        Map<String, String> params = new HashMap<>();
        params.put("credential", CREDENTIAL_TYPE);

        try {
            walletCredentialsController.downloadCredential(WALLET_ID, params, httpSession);
            fail("Expected InvalidRequestException");
        } catch (InvalidRequestException e) {
            assertEquals(ErrorConstants.INVALID_REQUEST.getErrorCode(), e.getErrorCode());
            assertEquals("invalid_request --> Issuer and credential type are required", e.getMessage());
        }
        verify(httpSession).getAttribute(SessionKeys.WALLET_ID);
        verify(httpSession).getAttribute(SessionKeys.WALLET_KEY);
        verifyNoInteractions(credentialUtilService, walletCredentialService);
    }

    @Test
    public void downloadCredentialTokenFetchFailureReturnsServiceUnavailable() throws Exception {
        Map<String, String> params = new HashMap<>();
        params.put("issuer", ISSUER_ID);
        params.put("credential", CREDENTIAL_TYPE);

        when(credentialUtilService.getTokenResponse(params, ISSUER_ID))
                .thenThrow(new ApiNotAccessibleException("API Error"));

        ResponseEntity<VerifiableCredentialResponseDTO> response = walletCredentialsController
                .downloadCredential(WALLET_ID, params, httpSession);

        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, response.getStatusCode());
        assertEquals(MediaType.APPLICATION_JSON, response.getHeaders().getContentType());
        verify(httpSession).getAttribute(SessionKeys.WALLET_ID);
        verify(httpSession).getAttribute(SessionKeys.WALLET_KEY);
        verify(credentialUtilService).getTokenResponse(params, ISSUER_ID);
        verifyNoInteractions(walletCredentialService);
    }

    @Test
    public void fetchAllCredentialsForGivenWalletSuccess() {
        List<VerifiableCredentialResponseDTO> credentials = Arrays.asList(new VerifiableCredentialResponseDTO());
        when(walletCredentialService.fetchAllCredentialsForWallet(WALLET_ID, BASE64_ENCODED_WALLET_KEY, LOCALE))
                .thenReturn(credentials);

        ResponseEntity<List<VerifiableCredentialResponseDTO>> response = walletCredentialsController
                .fetchAllCredentialsForGivenWallet(WALLET_ID, LOCALE, httpSession);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(credentials, response.getBody());
        verify(httpSession).getAttribute(SessionKeys.WALLET_ID);
        verify(httpSession).getAttribute(SessionKeys.WALLET_KEY);
        verify(walletCredentialService).fetchAllCredentialsForWallet(WALLET_ID, BASE64_ENCODED_WALLET_KEY, LOCALE);
    }

    @Test
    public void fetchAllCredentialsInvalidWalletIdThrowsInvalidRequestException() {
        when(httpSession.getAttribute(SessionKeys.WALLET_ID)).thenReturn("differentWalletId");

        try {
            walletCredentialsController.fetchAllCredentialsForGivenWallet(WALLET_ID, LOCALE, httpSession);
            fail("Expected InvalidRequestException");
        } catch (InvalidRequestException e) {
            assertEquals(ErrorConstants.INVALID_REQUEST.getErrorCode(), e.getErrorCode());
            assertEquals("invalid_request --> Wallet ID mismatch", e.getMessage());
        }
        verify(httpSession).getAttribute(SessionKeys.WALLET_ID);
        verifyNoInteractions(walletCredentialService);
    }

    @Test
    public void fetchAllCredentialsMissingWalletKeyThrowsInvalidRequestException() {
        when(httpSession.getAttribute(SessionKeys.WALLET_KEY)).thenReturn(null);

        try {
            walletCredentialsController.fetchAllCredentialsForGivenWallet(WALLET_ID, LOCALE, httpSession);
            fail("Expected InvalidRequestException");
        } catch (InvalidRequestException e) {
            assertEquals(ErrorConstants.INVALID_REQUEST.getErrorCode(), e.getErrorCode());
            assertEquals("invalid_request --> Wallet key not found in session", e.getMessage());
        }
        verify(httpSession).getAttribute(SessionKeys.WALLET_ID);
        verify(httpSession).getAttribute(SessionKeys.WALLET_KEY);
        verifyNoInteractions(walletCredentialService);
    }

    @Test
    public void getVerifiableCredentialSuccessInline() throws Exception {
        WalletCredentialResponseDTO responseDTO = new WalletCredentialResponseDTO();
        responseDTO.setFileName("credential.pdf");
        responseDTO.setFileContentStream(new InputStreamResource(new ByteArrayInputStream(new byte[0])));

        when(walletCredentialService.fetchVerifiableCredential(WALLET_ID, CREDENTIAL_ID, BASE64_ENCODED_WALLET_KEY, LOCALE))
                .thenReturn(responseDTO);

        ResponseEntity<InputStreamResource> response = walletCredentialsController
                .getVerifiableCredential(WALLET_ID, CREDENTIAL_ID, LOCALE, "inline", httpSession);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(MediaType.APPLICATION_PDF, response.getHeaders().getContentType());
        assertEquals("inline; filename=\"credential.pdf\"", response.getHeaders().getFirst(HttpHeaders.CONTENT_DISPOSITION));
        assertNotNull(response.getBody());
        verify(httpSession).getAttribute(SessionKeys.WALLET_ID);
        verify(httpSession).getAttribute(SessionKeys.WALLET_KEY);
        verify(walletCredentialService).fetchVerifiableCredential(WALLET_ID, CREDENTIAL_ID, BASE64_ENCODED_WALLET_KEY, LOCALE);
    }

    @Test
    public void getVerifiableCredentialSuccessDownload() throws Exception {
        WalletCredentialResponseDTO responseDTO = new WalletCredentialResponseDTO();
        responseDTO.setFileName("credential.pdf");
        responseDTO.setFileContentStream(new InputStreamResource(new ByteArrayInputStream(new byte[0])));

        when(walletCredentialService.fetchVerifiableCredential(WALLET_ID, CREDENTIAL_ID, BASE64_ENCODED_WALLET_KEY, LOCALE))
                .thenReturn(responseDTO);

        ResponseEntity<InputStreamResource> response = walletCredentialsController
                .getVerifiableCredential(WALLET_ID, CREDENTIAL_ID, LOCALE, "download", httpSession);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(MediaType.APPLICATION_PDF, response.getHeaders().getContentType());
        assertEquals("attachment; filename=\"credential.pdf\"", response.getHeaders().getFirst(HttpHeaders.CONTENT_DISPOSITION));
        assertNotNull(response.getBody());
        verify(httpSession).getAttribute(SessionKeys.WALLET_ID);
        verify(httpSession).getAttribute(SessionKeys.WALLET_KEY);
        verify(walletCredentialService).fetchVerifiableCredential(WALLET_ID, CREDENTIAL_ID, BASE64_ENCODED_WALLET_KEY, LOCALE);
    }

    @Test
    public void getVerifiableCredentialInvalidWalletIdThrowsInvalidRequestException() {
        when(httpSession.getAttribute(SessionKeys.WALLET_ID)).thenReturn("differentWalletId");

        try {
            walletCredentialsController.getVerifiableCredential(WALLET_ID, CREDENTIAL_ID, LOCALE, "inline", httpSession);
            fail("Expected InvalidRequestException");
        } catch (InvalidRequestException e) {
            assertEquals(ErrorConstants.INVALID_REQUEST.getErrorCode(), e.getErrorCode());
            assertEquals("invalid_request --> Wallet ID mismatch", e.getMessage());
        }
        verify(httpSession).getAttribute(SessionKeys.WALLET_ID);
        verifyNoInteractions(walletCredentialService);
    }

    @Test
    public void getVerifiableCredentialMissingWalletKeyThrowsInvalidRequestException() {
        when(httpSession.getAttribute(SessionKeys.WALLET_KEY)).thenReturn(null);

        try {
            walletCredentialsController.getVerifiableCredential(WALLET_ID, CREDENTIAL_ID, LOCALE, "inline", httpSession);
            fail("Expected InvalidRequestException");
        } catch (InvalidRequestException e) {
            assertEquals(ErrorConstants.INVALID_REQUEST.getErrorCode(), e.getErrorCode());
            assertEquals("invalid_request --> Wallet key not found in session", e.getMessage());
        }
        verify(httpSession).getAttribute(SessionKeys.WALLET_ID);
        verify(httpSession).getAttribute(SessionKeys.WALLET_KEY);
        verifyNoInteractions(walletCredentialService);
    }

    @Test
    public void getVerifiableCredentialNotFoundThrowsCredentialNotFoundException() throws Exception {
        when(walletCredentialService.fetchVerifiableCredential(WALLET_ID, CREDENTIAL_ID, BASE64_ENCODED_WALLET_KEY, LOCALE))
                .thenThrow(new CredentialNotFoundException("CREDENTIAL_NOT_FOUND", "Credential not found"));

        try {
            walletCredentialsController.getVerifiableCredential(WALLET_ID, CREDENTIAL_ID, LOCALE, "inline", httpSession);
            fail("Expected CredentialNotFoundException");
        } catch (CredentialNotFoundException e) {
            assertEquals("CREDENTIAL_NOT_FOUND", e.getErrorCode());
            assertEquals("CREDENTIAL_NOT_FOUND --> Credential not found", e.getMessage());
        }
        verify(httpSession).getAttribute(SessionKeys.WALLET_ID);
        verify(httpSession).getAttribute(SessionKeys.WALLET_KEY);
        verify(walletCredentialService).fetchVerifiableCredential(WALLET_ID, CREDENTIAL_ID, BASE64_ENCODED_WALLET_KEY, LOCALE);
    }

    @Test
    public void getVerifiableCredentialDecryptionExceptionThrowsProcessingException() throws Exception {
        when(walletCredentialService.fetchVerifiableCredential(WALLET_ID, CREDENTIAL_ID, BASE64_ENCODED_WALLET_KEY, LOCALE))
                .thenThrow(new CredentialProcessingException("DECRYPTION_ERROR", "Decryption failed"));

        try {
            walletCredentialsController.getVerifiableCredential(WALLET_ID, CREDENTIAL_ID, LOCALE, "inline", httpSession);
            fail("Expected CredentialProcessingException");
        } catch (CredentialProcessingException e) {
            assertEquals("DECRYPTION_ERROR", e.getErrorCode());
            assertEquals("DECRYPTION_ERROR --> Decryption failed", e.getMessage());
        }
        verify(httpSession).getAttribute(SessionKeys.WALLET_ID);
        verify(httpSession).getAttribute(SessionKeys.WALLET_KEY);
        verify(walletCredentialService).fetchVerifiableCredential(WALLET_ID, CREDENTIAL_ID, BASE64_ENCODED_WALLET_KEY, LOCALE);
    }
    @Test
    public void getVerifiableCredentialCorruptedEncryptedDataExceptionThrowsProcessingException() throws Exception {
        when(walletCredentialService.fetchVerifiableCredential(WALLET_ID, CREDENTIAL_ID, BASE64_ENCODED_WALLET_KEY, LOCALE))
                .thenThrow(new CredentialProcessingException("CORRUPTED_DATA", "Corrupted data"));

        try {
            walletCredentialsController.getVerifiableCredential(WALLET_ID, CREDENTIAL_ID, LOCALE, "inline", httpSession);
            fail("Expected CredentialProcessingException");
        } catch (CredentialProcessingException e) {
            assertEquals("CORRUPTED_DATA", e.getErrorCode());
            assertEquals("CORRUPTED_DATA --> Corrupted data", e.getMessage());
        }
        verify(httpSession).getAttribute(SessionKeys.WALLET_ID);
        verify(httpSession).getAttribute(SessionKeys.WALLET_KEY);
        verify(walletCredentialService).fetchVerifiableCredential(WALLET_ID, CREDENTIAL_ID, BASE64_ENCODED_WALLET_KEY, LOCALE);
    }

    @Test
    public void downloadCredentialExternalServiceUnavailableReturnsServiceUnavailable() throws Exception {
        Map<String, String> params = new HashMap<>();
        params.put("issuer", ISSUER_ID);
        params.put("credential", CREDENTIAL_TYPE);

        TokenResponseDTO tokenResponse = new TokenResponseDTO();
        when(credentialUtilService.getTokenResponse(params, ISSUER_ID)).thenReturn(tokenResponse);
        when(walletCredentialService.fetchAndStoreCredential(any(), any(), any(), any(), any(), any(), any()))
                .thenThrow(new ExternalServiceUnavailableException("SERVICE_UNAVAILABLE", "Service unavailable"));

        ResponseEntity<VerifiableCredentialResponseDTO> response = walletCredentialsController
                .downloadCredential(WALLET_ID, params, httpSession);

        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, response.getStatusCode());
        assertEquals(MediaType.APPLICATION_JSON, response.getHeaders().getContentType());
        verify(httpSession).getAttribute(SessionKeys.WALLET_ID);
        verify(httpSession).getAttribute(SessionKeys.WALLET_KEY);
        verify(credentialUtilService).getTokenResponse(params, ISSUER_ID);
        verify(walletCredentialService).fetchAndStoreCredential(eq(ISSUER_ID), eq(CREDENTIAL_TYPE), eq(tokenResponse),
                eq(VC_STORAGE_EXPIRY), eq(LOCALE), eq(WALLET_ID), eq(BASE64_ENCODED_WALLET_KEY));
    }
}