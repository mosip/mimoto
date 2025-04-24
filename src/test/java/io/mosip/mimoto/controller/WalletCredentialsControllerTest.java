package io.mosip.mimoto.controller;

import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.VerifiableCredentialResponseDTO;
import io.mosip.mimoto.dto.resident.WalletCredentialResponseDTO;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.service.WalletCredentialService;
import io.mosip.mimoto.util.CredentialUtilService;
import io.mosip.mimoto.util.WalletUtil;
import jakarta.servlet.http.HttpSession;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.core.io.InputStreamResource;
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

    @Test
    public void downloadCredentialSuccess() throws Exception {
        
        try (var walletUtilMock = mockStatic(WalletUtil.class)) {
            walletUtilMock.when(() -> WalletUtil.validateWalletId(httpSession, WALLET_ID)).thenAnswer(invocation -> null);
            walletUtilMock.when(() -> WalletUtil.getSessionWalletKey(httpSession)).thenReturn(BASE64_ENCODED_WALLET_KEY);

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
            walletUtilMock.verify(() -> WalletUtil.validateWalletId(httpSession, WALLET_ID));
            walletUtilMock.verify(() -> WalletUtil.getSessionWalletKey(httpSession));
            verify(credentialUtilService).getTokenResponse(params, ISSUER_ID);
            verify(walletCredentialService).fetchAndStoreCredential(eq(ISSUER_ID), eq(CREDENTIAL_TYPE), eq(tokenResponse),
                    eq(VC_STORAGE_EXPIRY), eq(LOCALE), eq(WALLET_ID), eq(BASE64_ENCODED_WALLET_KEY));
        }
    }

    @Test
    public void downloadCredentialTokenFetchFailureThrowsExternalServiceUnavailableException() throws Exception {
        
        try (var walletUtilMock = mockStatic(WalletUtil.class)) {
            walletUtilMock.when(() -> WalletUtil.validateWalletId(httpSession, WALLET_ID)).thenAnswer(invocation -> null);
            walletUtilMock.when(() -> WalletUtil.getSessionWalletKey(httpSession)).thenReturn(BASE64_ENCODED_WALLET_KEY);

            Map<String, String> params = new HashMap<>();
            params.put("issuer", ISSUER_ID);
            params.put("credential", CREDENTIAL_TYPE);

            when(credentialUtilService.getTokenResponse(params, ISSUER_ID))
                    .thenThrow(new ApiNotAccessibleException("API Error"));

            
            try {
                walletCredentialsController.downloadCredential(WALLET_ID, params, httpSession);
                fail("Expected ExternalServiceUnavailableException");
            } catch (ExternalServiceUnavailableException e) {
                // Expected
            }
            walletUtilMock.verify(() -> WalletUtil.validateWalletId(httpSession, WALLET_ID));
            verify(credentialUtilService).getTokenResponse(params, ISSUER_ID);
            verify(walletCredentialService, never()).fetchAndStoreCredential(any(), any(), any(), any(), any(), any(), any());
        }
    }

    @Test
    public void downloadCredentialServiceExceptionReturnsInternalServerError() throws Exception {
        
        try (var walletUtilMock = mockStatic(WalletUtil.class)) {
            walletUtilMock.when(() -> WalletUtil.validateWalletId(httpSession, WALLET_ID)).thenAnswer(invocation -> null);
            walletUtilMock.when(() -> WalletUtil.getSessionWalletKey(httpSession)).thenReturn(BASE64_ENCODED_WALLET_KEY);

            Map<String, String> params = new HashMap<>();
            params.put("issuer", ISSUER_ID);
            params.put("credential", CREDENTIAL_TYPE);

            TokenResponseDTO tokenResponse = new TokenResponseDTO();
            when(credentialUtilService.getTokenResponse(params, ISSUER_ID)).thenReturn(tokenResponse);
            when(walletCredentialService.fetchAndStoreCredential(any(), any(), any(), any(), any(), any(), any()))
                    .thenThrow(new RuntimeException("Service Error"));

            
            ResponseEntity<VerifiableCredentialResponseDTO> response = walletCredentialsController
                    .downloadCredential(WALLET_ID, params, httpSession);

            
            assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
            walletUtilMock.verify(() -> WalletUtil.validateWalletId(httpSession, WALLET_ID));
            walletUtilMock.verify(() -> WalletUtil.getSessionWalletKey(httpSession));
            verify(credentialUtilService).getTokenResponse(params, ISSUER_ID);
            verify(walletCredentialService).fetchAndStoreCredential(any(), any(), any(), any(), any(), any(), any());
        }
    }

    @Test
    public void fetchAllCredentialsForGivenWalletSuccess() {
        
        try (var walletUtilMock = mockStatic(WalletUtil.class)) {
            walletUtilMock.when(() -> WalletUtil.validateWalletId(httpSession, WALLET_ID)).thenAnswer(invocation -> null);
            walletUtilMock.when(() -> WalletUtil.getSessionWalletKey(httpSession)).thenReturn(BASE64_ENCODED_WALLET_KEY);

            List<VerifiableCredentialResponseDTO> credentials = Arrays.asList(new VerifiableCredentialResponseDTO());
            when(walletCredentialService.fetchAllCredentialsForWallet(WALLET_ID, BASE64_ENCODED_WALLET_KEY, LOCALE))
                    .thenReturn(credentials);

            
            ResponseEntity<List<VerifiableCredentialResponseDTO>> response = walletCredentialsController
                    .fetchAllCredentialsForGivenWallet(WALLET_ID, LOCALE, httpSession);

            
            assertEquals(HttpStatus.OK, response.getStatusCode());
            assertEquals(credentials, response.getBody());
            walletUtilMock.verify(() -> WalletUtil.validateWalletId(httpSession, WALLET_ID));
            walletUtilMock.verify(() -> WalletUtil.getSessionWalletKey(httpSession));
            verify(walletCredentialService).fetchAllCredentialsForWallet(WALLET_ID, BASE64_ENCODED_WALLET_KEY, LOCALE);
        }
    }

    @Test
    public void getVerifiableCredentialSuccessInline() throws Exception {
        
        try (var walletUtilMock = mockStatic(WalletUtil.class)) {
            walletUtilMock.when(() -> WalletUtil.validateWalletId(httpSession, WALLET_ID)).thenAnswer(invocation -> null);
            walletUtilMock.when(() -> WalletUtil.getSessionWalletKey(httpSession)).thenReturn(BASE64_ENCODED_WALLET_KEY);

            WalletCredentialResponseDTO responseDTO = new WalletCredentialResponseDTO();
            responseDTO.setFileName("credential.pdf");
            responseDTO.setFileContentStream(new InputStreamResource(new ByteArrayInputStream(new byte[0])));

            when(walletCredentialService.fetchVerifiableCredential(WALLET_ID, CREDENTIAL_ID, BASE64_ENCODED_WALLET_KEY, LOCALE))
                    .thenReturn(responseDTO);

            
            ResponseEntity<InputStreamResource> response = walletCredentialsController
                    .getVerifiableCredential(WALLET_ID, CREDENTIAL_ID, LOCALE, "inline", httpSession);

            
            assertEquals(HttpStatus.OK, response.getStatusCode());
            assertEquals(MediaType.APPLICATION_PDF, response.getHeaders().getContentType());
            assertEquals("inline; filename=\"credential.pdf\"", response.getHeaders().getFirst("Content-Disposition"));
            assertNotNull(response.getBody());
            walletUtilMock.verify(() -> WalletUtil.validateWalletId(httpSession, WALLET_ID));
            walletUtilMock.verify(() -> WalletUtil.getSessionWalletKey(httpSession));
            verify(walletCredentialService).fetchVerifiableCredential(WALLET_ID, CREDENTIAL_ID, BASE64_ENCODED_WALLET_KEY, LOCALE);
        }
    }

    @Test
    public void getVerifiableCredentialSuccessDownload() throws Exception {
        
        try (var walletUtilMock = mockStatic(WalletUtil.class)) {
            walletUtilMock.when(() -> WalletUtil.validateWalletId(httpSession, WALLET_ID)).thenAnswer(invocation -> null);
            walletUtilMock.when(() -> WalletUtil.getSessionWalletKey(httpSession)).thenReturn(BASE64_ENCODED_WALLET_KEY);

            WalletCredentialResponseDTO responseDTO = new WalletCredentialResponseDTO();
            responseDTO.setFileName("credential.pdf");
            responseDTO.setFileContentStream(new InputStreamResource(new ByteArrayInputStream(new byte[0])));

            when(walletCredentialService.fetchVerifiableCredential(WALLET_ID, CREDENTIAL_ID, BASE64_ENCODED_WALLET_KEY, LOCALE))
                    .thenReturn(responseDTO);

            
            ResponseEntity<InputStreamResource> response = walletCredentialsController
                    .getVerifiableCredential(WALLET_ID, CREDENTIAL_ID, LOCALE, "download", httpSession);

            
            assertEquals(HttpStatus.OK, response.getStatusCode());
            assertEquals("attachment; filename=\"credential.pdf\"", response.getHeaders().getFirst("Content-Disposition"));
            walletUtilMock.verify(() -> WalletUtil.validateWalletId(httpSession, WALLET_ID));
            walletUtilMock.verify(() -> WalletUtil.getSessionWalletKey(httpSession));
            verify(walletCredentialService).fetchVerifiableCredential(WALLET_ID, CREDENTIAL_ID, BASE64_ENCODED_WALLET_KEY, LOCALE);
        }
    }

    @Test
    public void getVerifiableCredentialDecryptionExceptionReturnsBadRequest() throws Exception {
        
        try (var walletUtilMock = mockStatic(WalletUtil.class)) {
            walletUtilMock.when(() -> WalletUtil.validateWalletId(httpSession, WALLET_ID)).thenAnswer(invocation -> null);
            walletUtilMock.when(() -> WalletUtil.getSessionWalletKey(httpSession)).thenReturn(BASE64_ENCODED_WALLET_KEY);

            when(walletCredentialService.fetchVerifiableCredential(WALLET_ID, CREDENTIAL_ID, BASE64_ENCODED_WALLET_KEY, LOCALE))
                    .thenThrow(new DecryptionException("DECRYPTION_ERROR", "Decryption failed"));

            
            ResponseEntity<InputStreamResource> response = walletCredentialsController
                    .getVerifiableCredential(WALLET_ID, CREDENTIAL_ID, LOCALE, "inline", httpSession);

            
            assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
            assertEquals(MediaType.APPLICATION_JSON, response.getHeaders().getContentType());
            walletUtilMock.verify(() -> WalletUtil.validateWalletId(httpSession, WALLET_ID));
            walletUtilMock.verify(() -> WalletUtil.getSessionWalletKey(httpSession));
            verify(walletCredentialService).fetchVerifiableCredential(WALLET_ID, CREDENTIAL_ID, BASE64_ENCODED_WALLET_KEY, LOCALE);
        }
    }

    @Test
    public void getVerifiableCredentialCorruptedEncryptedDataExceptionReturnsUnprocessableEntity() throws Exception {
        
        try (var walletUtilMock = mockStatic(WalletUtil.class)) {
            walletUtilMock.when(() -> WalletUtil.validateWalletId(httpSession, WALLET_ID)).thenAnswer(invocation -> null);
            walletUtilMock.when(() -> WalletUtil.getSessionWalletKey(httpSession)).thenReturn(BASE64_ENCODED_WALLET_KEY);

            when(walletCredentialService.fetchVerifiableCredential(WALLET_ID, CREDENTIAL_ID, BASE64_ENCODED_WALLET_KEY, LOCALE))
                    .thenThrow(new CorruptedEncryptedDataException("CORRUPTED_DATA", "Corrupted data"));

            
            ResponseEntity<InputStreamResource> response = walletCredentialsController
                    .getVerifiableCredential(WALLET_ID, CREDENTIAL_ID, LOCALE, "inline", httpSession);

            
            assertEquals(HttpStatus.UNPROCESSABLE_ENTITY, response.getStatusCode());
            assertEquals(MediaType.APPLICATION_JSON, response.getHeaders().getContentType());
            walletUtilMock.verify(() -> WalletUtil.validateWalletId(httpSession, WALLET_ID));
            walletUtilMock.verify(() -> WalletUtil.getSessionWalletKey(httpSession));
            verify(walletCredentialService).fetchVerifiableCredential(WALLET_ID, CREDENTIAL_ID, BASE64_ENCODED_WALLET_KEY, LOCALE);
        }
    }

    @Test
    public void downloadCredentialInvalidWalletIdThrowsInvalidRequestException() {
        
        try (var walletUtilMock = mockStatic(WalletUtil.class)) {
            walletUtilMock.when(() -> WalletUtil.validateWalletId(httpSession, WALLET_ID))
                    .thenThrow(new InvalidRequestException("INVALID_REQUEST", "Invalid Wallet Id"));

            Map<String, String> params = new HashMap<>();
            params.put("issuer", ISSUER_ID);
            params.put("credential", CREDENTIAL_TYPE);

            
            try {
                walletCredentialsController.downloadCredential(WALLET_ID, params, httpSession);
                fail("Expected InvalidRequestException");
            } catch (InvalidRequestException e) {
                // Expected
            }
            walletUtilMock.verify(() -> WalletUtil.validateWalletId(httpSession, WALLET_ID));
            verifyNoInteractions(credentialUtilService, walletCredentialService);
        }
    }
}
