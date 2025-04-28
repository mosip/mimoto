package io.mosip.mimoto.service;

import io.mosip.mimoto.dbentity.CredentialMetadata;
import io.mosip.mimoto.dbentity.VerifiableCredential;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.CredentialsSupportedResponse;
import io.mosip.mimoto.dto.mimoto.IssuerConfig;
import io.mosip.mimoto.dto.mimoto.VerifiableCredentialResponseDTO;
import io.mosip.mimoto.dto.resident.WalletCredentialResponseDTO;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.repository.WalletCredentialsRepository;
import io.mosip.mimoto.service.impl.WalletCredentialServiceImpl;
import io.mosip.mimoto.util.CredentialProcessor;
import io.mosip.mimoto.util.CredentialUtilService;
import io.mosip.mimoto.util.EncryptionDecryptionUtil;
import io.mosip.mimoto.util.WalletCredentialResponseDTOFactory;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.core.io.InputStreamResource;

import java.io.ByteArrayInputStream;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static io.mosip.mimoto.exception.ErrorConstants.*;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class WalletCredentialServiceTest {

    @InjectMocks
    private WalletCredentialServiceImpl walletCredentialService;

    @Mock
    private WalletCredentialsRepository walletCredentialsRepository;

    @Mock
    private IssuersService issuersService;

    @Mock
    private CredentialProcessor credentialProcessor;

    @Mock
    private CredentialUtilService credentialUtilService;

    @Mock
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    private final String walletId = "wallet123";
    private final String issuerId = "issuer123";
    private final String credentialType = "CredentialType1";
    private final String credentialId = "cred123";
    private final String base64Key = "ZHVtbXlrZXkxMjM0NTY3OA=="; // Base64 of "dummykey12345678"
    private final String locale = "en";
    private final String credentialValidity = "1";

    private TokenResponseDTO tokenResponse;
    private VerifiableCredential verifiableCredential;
    private IssuerConfig issuerConfig;

    @Before
    public void setUp() {
        tokenResponse = new TokenResponseDTO();
        tokenResponse.setAccess_token("accessToken");

        verifiableCredential = new VerifiableCredential();
        verifiableCredential.setId(credentialId);
        verifiableCredential.setWalletId(walletId);
        verifiableCredential.setCredential("encryptedCredential");
        CredentialMetadata metadata = new CredentialMetadata();
        metadata.setIssuerId(issuerId);
        metadata.setCredentialType(credentialType);
        verifiableCredential.setCredentialMetadata(metadata);
        verifiableCredential.setCreatedAt(Instant.now());
        verifiableCredential.setUpdatedAt(Instant.now());

        IssuerDTO issuerDTO = new IssuerDTO();
        issuerDTO.setIssuer_id(issuerId);
        CredentialIssuerWellKnownResponse wellKnownResponse = new CredentialIssuerWellKnownResponse();
        CredentialsSupportedResponse credentialsSupportedResponse = new CredentialsSupportedResponse();
        issuerConfig = new IssuerConfig(issuerDTO, wellKnownResponse, credentialsSupportedResponse);
    }

    @Test
    public void shouldFetchAndStoreCredentialSuccessfully() throws Exception {
        String mosipIssuerId = "Mosip";
        VerifiableCredentialResponseDTO expectedResponse = new VerifiableCredentialResponseDTO();
        expectedResponse.setCredentialId(credentialId);

        when(walletCredentialsRepository.existsByIssuerIdAndCredentialTypeAndWalletId(mosipIssuerId, credentialType, walletId)).thenReturn(false);
        when(credentialProcessor.processAndStoreCredential(eq(tokenResponse), eq(credentialType), eq(walletId), eq(base64Key), eq(credentialValidity), eq(mosipIssuerId), eq(locale)))
                .thenReturn(expectedResponse);

        VerifiableCredentialResponseDTO actualResponse = walletCredentialService.fetchAndStoreCredential(
                mosipIssuerId, credentialType, tokenResponse, credentialValidity, locale, walletId, base64Key);

        assertEquals(expectedResponse, actualResponse);
        verify(walletCredentialsRepository).existsByIssuerIdAndCredentialTypeAndWalletId(mosipIssuerId, credentialType, walletId);
        verify(credentialProcessor).processAndStoreCredential(eq(tokenResponse), eq(credentialType), eq(walletId), eq(base64Key), eq(credentialValidity), eq(mosipIssuerId), eq(locale));
    }

    @Test
    public void shouldThrowDuplicateCredentialExceptionForMosipIssuer() {
        when(walletCredentialsRepository.existsByIssuerIdAndCredentialTypeAndWalletId("Mosip", credentialType, walletId)).thenReturn(true);

        CredentialProcessingException exception = assertThrows(CredentialProcessingException.class, () ->
                walletCredentialService.fetchAndStoreCredential("Mosip", credentialType, tokenResponse, credentialValidity, locale, walletId, base64Key));

        assertEquals(CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(), exception.getErrorCode());
        assertEquals("credential_download_error --> Duplicate credential for issuer and type", exception.getMessage());
        verify(walletCredentialsRepository).existsByIssuerIdAndCredentialTypeAndWalletId("Mosip", credentialType, walletId);
        verifyNoInteractions(credentialProcessor);
    }

    @Test
    public void shouldFetchAndStoreNonMosipIssuerCredential() throws Exception {
        VerifiableCredentialResponseDTO expectedResponse = new VerifiableCredentialResponseDTO();
        expectedResponse.setCredentialId(credentialId);

        when(credentialProcessor.processAndStoreCredential(eq(tokenResponse), eq(credentialType), eq(walletId), eq(base64Key), eq(credentialValidity), eq(issuerId), eq(locale)))
                .thenReturn(expectedResponse);

        VerifiableCredentialResponseDTO actualResponse = walletCredentialService.fetchAndStoreCredential(
                issuerId, credentialType, tokenResponse, credentialValidity, locale, walletId, base64Key);

        assertEquals(expectedResponse, actualResponse);
        verify(credentialProcessor).processAndStoreCredential(eq(tokenResponse), eq(credentialType), eq(walletId), eq(base64Key), eq(credentialValidity), eq(issuerId), eq(locale));
    }

    @Test
    public void shouldThrowExternalServiceUnavailableException() throws Exception {
        String mosipIssuerId = "Mosip"; // Use Mosip to trigger repository check

        when(walletCredentialsRepository.existsByIssuerIdAndCredentialTypeAndWalletId(mosipIssuerId, credentialType, walletId)).thenReturn(false);
        when(credentialProcessor.processAndStoreCredential(any(), anyString(), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenThrow(new ExternalServiceUnavailableException("SERVICE_UNAVAILABLE", "Service unavailable"));

        ExternalServiceUnavailableException exception = assertThrows(ExternalServiceUnavailableException.class, () ->
                walletCredentialService.fetchAndStoreCredential(mosipIssuerId, credentialType, tokenResponse, credentialValidity, locale, walletId, base64Key));

        assertEquals("SERVICE_UNAVAILABLE", exception.getErrorCode());
        assertEquals("SERVICE_UNAVAILABLE --> Service unavailable", exception.getMessage());
        verify(walletCredentialsRepository).existsByIssuerIdAndCredentialTypeAndWalletId(mosipIssuerId, credentialType, walletId);
        verify(credentialProcessor).processAndStoreCredential(eq(tokenResponse), eq(credentialType), eq(walletId), eq(base64Key), eq(credentialValidity), eq(mosipIssuerId), eq(locale));
    }

    @Test
    public void shouldFetchAllCredentialsForWalletSuccessfully() throws Exception {
        VerifiableCredentialResponseDTO responseDTO = new VerifiableCredentialResponseDTO();
        responseDTO.setCredentialId(credentialId);

        when(walletCredentialsRepository.findByWalletId(walletId)).thenReturn(List.of(verifiableCredential));
        when(issuersService.getIssuerConfig(issuerId, credentialType)).thenReturn(issuerConfig);

        try (MockedStatic<WalletCredentialResponseDTOFactory> factoryMock = mockStatic(WalletCredentialResponseDTOFactory.class)) {
            factoryMock.when(() -> WalletCredentialResponseDTOFactory.buildCredentialResponseDTO(issuerConfig, locale, credentialId))
                    .thenReturn(responseDTO);

            List<VerifiableCredentialResponseDTO> actualCredentials = walletCredentialService.fetchAllCredentialsForWallet(walletId, base64Key, locale);

            assertEquals(1, actualCredentials.size());
            assertEquals(responseDTO, actualCredentials.get(0));
            verify(walletCredentialsRepository).findByWalletId(walletId);
            verify(issuersService).getIssuerConfig(issuerId, credentialType);
            factoryMock.verify(() -> WalletCredentialResponseDTOFactory.buildCredentialResponseDTO(issuerConfig, locale, credentialId));
        }
    }

    @Test
    public void shouldHandleIssuerConfigFetchFailure() throws Exception {
        VerifiableCredentialResponseDTO responseDTO = new VerifiableCredentialResponseDTO();
        responseDTO.setCredentialId(credentialId);

        when(walletCredentialsRepository.findByWalletId(walletId)).thenReturn(List.of(verifiableCredential));
        when(issuersService.getIssuerConfig(issuerId, credentialType)).thenThrow(new ApiNotAccessibleException("API error"));

        try (MockedStatic<WalletCredentialResponseDTOFactory> factoryMock = mockStatic(WalletCredentialResponseDTOFactory.class)) {
            factoryMock.when(() -> WalletCredentialResponseDTOFactory.buildCredentialResponseDTO(null, locale, credentialId))
                    .thenReturn(responseDTO);

            List<VerifiableCredentialResponseDTO> actualCredentials = walletCredentialService.fetchAllCredentialsForWallet(walletId, base64Key, locale);

            assertEquals(1, actualCredentials.size());
            assertEquals(responseDTO, actualCredentials.get(0));
            verify(walletCredentialsRepository).findByWalletId(walletId);
            verify(issuersService).getIssuerConfig(issuerId, credentialType);
            factoryMock.verify(() -> WalletCredentialResponseDTOFactory.buildCredentialResponseDTO(null, locale, credentialId));
        }
    }

    @Test
    public void shouldFetchVerifiableCredentialSuccessfully() throws Exception {
        String decryptedCredential = "{\"credential\":\"test\"}";
        WalletCredentialResponseDTO expectedResponse = new WalletCredentialResponseDTO();
        expectedResponse.setFileName(credentialType);
        expectedResponse.setFileContentStream(new InputStreamResource(new ByteArrayInputStream("PDF Content".getBytes())));

        when(walletCredentialsRepository.findByIdAndWalletId(credentialId, walletId)).thenReturn(Optional.of(verifiableCredential));
        when(encryptionDecryptionUtil.decryptCredential("encryptedCredential", base64Key)).thenReturn(decryptedCredential);
        when(credentialUtilService.generateCredentialResponse(eq(decryptedCredential), any(), eq(locale))).thenReturn(expectedResponse);

        WalletCredentialResponseDTO actualResponse = walletCredentialService.fetchVerifiableCredential(walletId, credentialId, base64Key, locale);

        assertNotNull(actualResponse);
        assertEquals(expectedResponse, actualResponse);
        assertEquals(credentialType, actualResponse.getFileName());
        verify(walletCredentialsRepository).findByIdAndWalletId(credentialId, walletId);
        verify(encryptionDecryptionUtil).decryptCredential("encryptedCredential", base64Key);
        verify(credentialUtilService).generateCredentialResponse(eq(decryptedCredential), any(), eq(locale));
    }

    @Test
    public void shouldThrowCredentialNotFoundException() {
        when(walletCredentialsRepository.findByIdAndWalletId(credentialId, walletId)).thenReturn(Optional.empty());

        CredentialNotFoundException exception = assertThrows(CredentialNotFoundException.class, () ->
                walletCredentialService.fetchVerifiableCredential(walletId, credentialId, base64Key, locale));

        assertEquals(RESOURCE_NOT_FOUND.getErrorCode(), exception.getErrorCode());
        assertEquals(RESOURCE_NOT_FOUND.getErrorCode() +" --> "+RESOURCE_NOT_FOUND.getErrorMessage(), exception.getMessage());
        verify(walletCredentialsRepository).findByIdAndWalletId(credentialId, walletId);
        verifyNoInteractions(encryptionDecryptionUtil, credentialUtilService);
    }

    @Test
    public void shouldThrowCredentialProcessingExceptionOnDecryptionFailure() throws Exception {
        when(walletCredentialsRepository.findByIdAndWalletId(credentialId, walletId)).thenReturn(Optional.of(verifiableCredential));
        when(encryptionDecryptionUtil.decryptCredential("encryptedCredential", base64Key))
                .thenThrow(new DecryptionException("DECRYPTION_ERROR", "Decryption failed"));

        CredentialProcessingException exception = assertThrows(CredentialProcessingException.class, () ->
                walletCredentialService.fetchVerifiableCredential(walletId, credentialId, base64Key, locale));

        assertEquals(CREDENTIAL_FETCH_EXCEPTION.getErrorCode(), exception.getErrorCode());
        verify(walletCredentialsRepository).findByIdAndWalletId(credentialId, walletId);
        verify(encryptionDecryptionUtil).decryptCredential("encryptedCredential", base64Key);
        verifyNoInteractions(credentialUtilService);
    }
}