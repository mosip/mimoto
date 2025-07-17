package io.mosip.mimoto.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.model.CredentialMetadata;
import io.mosip.mimoto.model.VerifiableCredential;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.dto.resident.WalletCredentialResponseDTO;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.repository.WalletCredentialsRepository;
import io.mosip.mimoto.service.impl.WalletCredentialServiceImpl;
import io.mosip.mimoto.util.CredentialProcessor;
import io.mosip.mimoto.util.EncryptionDecryptionUtil;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Field;
import java.time.Instant;
import java.util.List;
import java.util.Map;
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
    private ObjectMapper objectMapper;

    @Mock
    private CredentialProcessor credentialProcessor;

    @Mock
    private CredentialPDFGeneratorService credentialPDFGeneratorService;

    @Mock
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    private final String walletId = "wallet123";
    private final String issuerId = "issuer123";
    private final String credentialType = "CredentialType1";
    private final String credentialId = "cred123";
    private final String base64Key = "ZHVtbXlrZXkxMjM0NTY3OA=="; // Base64 of "dummykey12345678"
    private final String locale = "en";

    private TokenResponseDTO tokenResponse;
    private VerifiableCredential verifiableCredential;
    private IssuerConfig issuerConfig;

    @Before
    public void setUp() throws Exception {
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

        Field field = WalletCredentialServiceImpl.class.getDeclaredField("issuersWithSingleVcLimit");
        field.setAccessible(true);
        field.set(walletCredentialService, "Mosip");
    }

    @Test
    public void shouldDownloadVCAndStoreInDBSuccessfully() throws Exception {
        String mosipIssuerId = "Mosip";
        VerifiableCredentialResponseDTO expectedResponse = new VerifiableCredentialResponseDTO();
        expectedResponse.setCredentialId(credentialId);

        when(walletCredentialsRepository.existsByIssuerIdAndCredentialTypeAndWalletId(mosipIssuerId, credentialType, walletId)).thenReturn(false);
        when(credentialProcessor.downloadCredentialAndStoreInDB(tokenResponse, credentialType, walletId, base64Key, mosipIssuerId, locale))
                .thenReturn(expectedResponse);

        VerifiableCredentialResponseDTO actualResponse = walletCredentialService.downloadVCAndStoreInDB(
                mosipIssuerId, credentialType, tokenResponse, locale, walletId, base64Key);

        assertEquals(expectedResponse, actualResponse);
        verify(walletCredentialsRepository).existsByIssuerIdAndCredentialTypeAndWalletId(mosipIssuerId, credentialType, walletId);
        verify(credentialProcessor).downloadCredentialAndStoreInDB(tokenResponse, credentialType, walletId, base64Key, mosipIssuerId, locale);
    }

    @Test
    public void shouldThrowDuplicateCredentialExceptionForMosipIssuer() {
        when(walletCredentialsRepository.existsByIssuerIdAndCredentialTypeAndWalletId("Mosip", credentialType, walletId)).thenReturn(true);

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                walletCredentialService.downloadVCAndStoreInDB("Mosip", credentialType, tokenResponse, locale, walletId, base64Key));

        assertEquals(CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(), exception.getErrorCode());
        assertEquals("credential_download_error --> Duplicate credential for issuer and type", exception.getMessage());
        verify(walletCredentialsRepository).existsByIssuerIdAndCredentialTypeAndWalletId("Mosip", credentialType, walletId);
        verifyNoInteractions(credentialProcessor);
    }

    @Test
    public void shouldFetchAndStoreNonMosipIssuerCredential() throws Exception {
        VerifiableCredentialResponseDTO expectedResponse = new VerifiableCredentialResponseDTO();
        expectedResponse.setCredentialId(credentialId);

        when(credentialProcessor.downloadCredentialAndStoreInDB(tokenResponse, credentialType, walletId, base64Key, issuerId, locale))
                .thenReturn(expectedResponse);

        VerifiableCredentialResponseDTO actualResponse = walletCredentialService.downloadVCAndStoreInDB(
                issuerId, credentialType, tokenResponse, locale, walletId, base64Key);

        assertEquals(expectedResponse, actualResponse);
        verify(credentialProcessor).downloadCredentialAndStoreInDB(tokenResponse, credentialType, walletId, base64Key, issuerId, locale);
    }

    @Test
    public void shouldThrowExternalServiceUnavailableException() throws Exception {
        String mosipIssuerId = "Mosip"; // Use Mosip to trigger repository check

        when(walletCredentialsRepository.existsByIssuerIdAndCredentialTypeAndWalletId(mosipIssuerId, credentialType, walletId)).thenReturn(false);
        when(credentialProcessor.downloadCredentialAndStoreInDB(any(), anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenThrow(new ExternalServiceUnavailableException("SERVICE_UNAVAILABLE", "Service unavailable"));

        ExternalServiceUnavailableException exception = assertThrows(ExternalServiceUnavailableException.class, () ->
                walletCredentialService.downloadVCAndStoreInDB(mosipIssuerId, credentialType, tokenResponse, locale, walletId, base64Key));

        assertEquals("SERVICE_UNAVAILABLE", exception.getErrorCode());
        assertEquals("SERVICE_UNAVAILABLE --> Service unavailable", exception.getMessage());
        verify(walletCredentialsRepository).existsByIssuerIdAndCredentialTypeAndWalletId(mosipIssuerId, credentialType, walletId);
        verify(credentialProcessor).downloadCredentialAndStoreInDB(tokenResponse, credentialType, walletId, base64Key, mosipIssuerId, locale);
    }

    @Test
    public void shouldFetchAllCredentialsForWalletSuccessfully() throws Exception {
        VerifiableCredentialResponseDTO responseDTO = new VerifiableCredentialResponseDTO();
        responseDTO.setCredentialId(credentialId);

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(walletId)).thenReturn(List.of(verifiableCredential));
        when(issuersService.getIssuerConfig(issuerId, credentialType)).thenReturn(issuerConfig);

        try (MockedStatic<VerifiableCredentialResponseDTO> factoryMock = mockStatic(VerifiableCredentialResponseDTO.class)) {
            factoryMock.when(() -> VerifiableCredentialResponseDTO.fromIssuerConfig(issuerConfig, locale, credentialId))
                    .thenReturn(responseDTO);

            List<VerifiableCredentialResponseDTO> actualCredentials = walletCredentialService.fetchAllCredentialsForWallet(walletId, base64Key, locale);

            assertEquals(1, actualCredentials.size());
            assertEquals(responseDTO, actualCredentials.getFirst());
            verify(walletCredentialsRepository).findByWalletIdOrderByCreatedAtDesc(walletId);
            verify(issuersService).getIssuerConfig(issuerId, credentialType);
            factoryMock.verify(() -> VerifiableCredentialResponseDTO.fromIssuerConfig(issuerConfig, locale, credentialId));
        }
    }

    @Test
    public void shouldHandleIssuerConfigFetchFailure() throws Exception {
        VerifiableCredentialResponseDTO responseDTO = new VerifiableCredentialResponseDTO();
        responseDTO.setCredentialId(credentialId);

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(walletId)).thenReturn(List.of(verifiableCredential));
        when(issuersService.getIssuerConfig(issuerId, credentialType)).thenThrow(new ApiNotAccessibleException("API error"));

        try (MockedStatic<VerifiableCredentialResponseDTO> factoryMock = mockStatic(VerifiableCredentialResponseDTO.class)) {
            factoryMock.when(() -> VerifiableCredentialResponseDTO.fromIssuerConfig(null, locale, credentialId))
                    .thenReturn(responseDTO);

            List<VerifiableCredentialResponseDTO> actualCredentials = walletCredentialService.fetchAllCredentialsForWallet(walletId, base64Key, locale);

            assertEquals(1, actualCredentials.size());
            assertEquals(responseDTO, actualCredentials.getFirst());
            verify(walletCredentialsRepository).findByWalletIdOrderByCreatedAtDesc(walletId);
            verify(issuersService).getIssuerConfig(issuerId, credentialType);
            factoryMock.verify(() -> VerifiableCredentialResponseDTO.fromIssuerConfig(null, locale, credentialId));
        }
    }

    @Test
    public void shouldFetchVerifiableCredentialSuccessfully() throws Exception {
        // Mocked VC JSON as String
        VCCredentialResponse vcResponse = VCCredentialResponse.builder()
                .format("ldp_vc")
                .credential(VCCredentialProperties.builder()
                        .type(List.of(credentialType))
                        .issuer("issuer123")
                        .issuanceDate("2024-01-01T00:00:00Z")
                        .credentialSubject(Map.of("name", "John Doe"))
                        .build())
                .build();

        String decryptedCredentialJson = new ObjectMapper().writeValueAsString(vcResponse);

        // Setup repository
        when(walletCredentialsRepository.findByIdAndWalletId(credentialId, walletId))
                .thenReturn(Optional.of(verifiableCredential));

        // Setup decryption
        when(encryptionDecryptionUtil.decryptCredential("encryptedCredential", base64Key))
                .thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(decryptedCredentialJson, VCCredentialResponse.class))
                .thenReturn(vcResponse);
        // IssuerDTO
        IssuerDTO issuerDTO = new IssuerDTO();
        issuerDTO.setIssuer_id(issuerId);
        when(issuersService.getIssuerDetails(issuerId)).thenReturn(issuerDTO);

        // Credential Definition that matches VC type
        CredentialDefinitionResponseDto credentialDefinition = new CredentialDefinitionResponseDto();
        credentialDefinition.setType(List.of(credentialType));
        credentialDefinition.setCredentialSubject(Map.of()); // safe stub
        credentialDefinition.setContext(List.of("https://www.w3.org/2018/credentials/v1"));

        // Full IssuerConfig
        CredentialsSupportedResponse supportedResponse = new CredentialsSupportedResponse();
        supportedResponse.setCredentialDefinition(credentialDefinition);
        supportedResponse.setProofTypesSupported(Map.of("ldp_vc", new ProofTypesSupported()));
        supportedResponse.setDisplay(List.of());
        supportedResponse.setFormat("ldp_vc");
        supportedResponse.setScope("scope");

        IssuerConfig issuerConfig = new IssuerConfig(issuerDTO, new CredentialIssuerWellKnownResponse(), supportedResponse);

        when(issuersService.getIssuerConfig(issuerId, credentialType)).thenReturn(issuerConfig);

        // Setup PDF stream
        ByteArrayInputStream pdfContent = new ByteArrayInputStream("PDF Content".getBytes());
        when(credentialPDFGeneratorService.generatePdfForVerifiableCredentials(
                eq(credentialType),
                any(VCCredentialResponse.class),
                eq(issuerDTO),
                eq(supportedResponse),
                eq(""),
                eq(null),
                eq(locale)
        )).thenReturn(pdfContent);

        // Run
        WalletCredentialResponseDTO actualResponse = walletCredentialService.fetchVerifiableCredential(walletId, credentialId, base64Key, locale);

        // Assert
        assertNotNull(actualResponse);
        assertEquals(String.format("%s_credential.pdf", credentialType), actualResponse.getFileName());
        assertNotNull(actualResponse.getFileContentStream());

        verify(walletCredentialsRepository).findByIdAndWalletId(credentialId, walletId);
        verify(encryptionDecryptionUtil).decryptCredential("encryptedCredential", base64Key);
        verify(issuersService).getIssuerDetails(issuerId);
        verify(issuersService).getIssuerConfig(issuerId, credentialType);
        verify(credentialPDFGeneratorService).generatePdfForVerifiableCredentials(
                eq(credentialType),
                any(VCCredentialResponse.class),
                eq(issuerDTO),
                eq(supportedResponse),
                eq(""),
                eq(null),
                eq(locale)
        );
    }



    @Test
    public void shouldThrowCredentialNotFoundException() {
        when(walletCredentialsRepository.findByIdAndWalletId(credentialId, walletId)).thenReturn(Optional.empty());

        CredentialNotFoundException exception = assertThrows(CredentialNotFoundException.class, () ->
                walletCredentialService.fetchVerifiableCredential(walletId, credentialId, base64Key, locale));

        assertEquals(RESOURCE_NOT_FOUND.getErrorCode(), exception.getErrorCode());
        assertEquals(RESOURCE_NOT_FOUND.getErrorCode() +" --> "+RESOURCE_NOT_FOUND.getErrorMessage(), exception.getMessage());
        verify(walletCredentialsRepository).findByIdAndWalletId(credentialId, walletId);
        verifyNoInteractions(encryptionDecryptionUtil, credentialPDFGeneratorService);
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
        verifyNoInteractions(credentialPDFGeneratorService);
    }

    @Test
    public void shouldDeleteCredentialSuccessfully() throws Exception {
        when(walletCredentialsRepository.findByIdAndWalletId(credentialId, walletId)).thenReturn(Optional.of(verifiableCredential));

        walletCredentialService.deleteCredential(credentialId, walletId);

        verify(walletCredentialsRepository).findByIdAndWalletId(credentialId, walletId);
        verify(walletCredentialsRepository).deleteById(credentialId);
    }

    @Test
    public void shouldThrowCredentialNotFoundExceptionWhenDeletingNonExistentCredential() {
        when(walletCredentialsRepository.findByIdAndWalletId(credentialId, walletId)).thenReturn(Optional.empty());

        CredentialNotFoundException exception = assertThrows(CredentialNotFoundException.class, () ->
                walletCredentialService.deleteCredential(credentialId, walletId));

        assertEquals(RESOURCE_NOT_FOUND.getErrorCode(), exception.getErrorCode());
        assertEquals(RESOURCE_NOT_FOUND.getErrorCode() + " --> " + RESOURCE_NOT_FOUND.getErrorMessage(), exception.getMessage());
        verify(walletCredentialsRepository).findByIdAndWalletId(credentialId, walletId);
        verify(walletCredentialsRepository, never()).deleteById(anyString());
    }

    @Test
    public void shouldThrowCredentialProcessingExceptionOnJsonProcessingError() throws Exception {
        when(walletCredentialsRepository.findByIdAndWalletId(credentialId, walletId)).thenReturn(Optional.of(verifiableCredential));
        when(encryptionDecryptionUtil.decryptCredential("encryptedCredential", base64Key)).thenReturn("bad-json");
        when(objectMapper.readValue("bad-json", VCCredentialResponse.class)).thenThrow(new com.fasterxml.jackson.core.JsonProcessingException("error") {});

        CredentialProcessingException exception = assertThrows(CredentialProcessingException.class, () ->
                walletCredentialService.fetchVerifiableCredential(walletId, credentialId, base64Key, locale));

        assertEquals(CREDENTIAL_FETCH_EXCEPTION.getErrorCode(), exception.getErrorCode());
        verify(walletCredentialsRepository).findByIdAndWalletId(credentialId, walletId);
        verify(encryptionDecryptionUtil).decryptCredential("encryptedCredential", base64Key);
        verify(objectMapper).readValue("bad-json", VCCredentialResponse.class);
    }

    @Test
    public void shouldThrowCredentialProcessingExceptionOnNullIssuerConfig() throws Exception {
        when(walletCredentialsRepository.findByIdAndWalletId(credentialId, walletId)).thenReturn(Optional.of(verifiableCredential));
        when(encryptionDecryptionUtil.decryptCredential("encryptedCredential", base64Key)).thenReturn("{}");
        VCCredentialResponse vcResponse = VCCredentialResponse.builder().credential(VCCredentialProperties.builder().type(List.of(credentialType)).build()).build();
        when(objectMapper.readValue(anyString(), eq(VCCredentialResponse.class))).thenReturn(vcResponse);
        when(issuersService.getIssuerDetails(issuerId)).thenReturn(new IssuerDTO());
        when(issuersService.getIssuerConfig(issuerId, credentialType)).thenReturn(null);

        CredentialProcessingException exception = assertThrows(CredentialProcessingException.class, () ->
                walletCredentialService.fetchVerifiableCredential(walletId, credentialId, base64Key, locale));

        assertEquals(CREDENTIAL_FETCH_EXCEPTION.getErrorCode(), exception.getErrorCode());
    }

    @Test
    public void shouldThrowCredentialProcessingExceptionOnCredentialTypeMismatch() throws Exception {
        when(walletCredentialsRepository.findByIdAndWalletId(credentialId, walletId)).thenReturn(Optional.of(verifiableCredential));
        when(encryptionDecryptionUtil.decryptCredential("encryptedCredential", base64Key)).thenReturn("{}");
        VCCredentialResponse vcResponse = VCCredentialResponse.builder().credential(VCCredentialProperties.builder().type(List.of("OtherType")).build()).build();
        when(objectMapper.readValue(anyString(), eq(VCCredentialResponse.class))).thenReturn(vcResponse);
        when(issuersService.getIssuerDetails(issuerId)).thenReturn(new IssuerDTO());

        CredentialDefinitionResponseDto credentialDefinition = new CredentialDefinitionResponseDto();
        credentialDefinition.setType(List.of(credentialType));
        CredentialsSupportedResponse supportedResponse = new CredentialsSupportedResponse();
        supportedResponse.setCredentialDefinition(credentialDefinition);

        IssuerConfig issuerConfig = new IssuerConfig(new IssuerDTO(), new CredentialIssuerWellKnownResponse(), supportedResponse);
        when(issuersService.getIssuerConfig(issuerId, credentialType)).thenReturn(issuerConfig);

        CredentialProcessingException exception = assertThrows(CredentialProcessingException.class, () ->
                walletCredentialService.fetchVerifiableCredential(walletId, credentialId, base64Key, locale));

        assertEquals(CREDENTIAL_FETCH_EXCEPTION.getErrorCode(), exception.getErrorCode());
    }

    @Test
    public void shouldThrowCredentialProcessingExceptionOnIssuerServiceException() throws Exception {
        when(walletCredentialsRepository.findByIdAndWalletId(credentialId, walletId)).thenReturn(Optional.of(verifiableCredential));
        when(encryptionDecryptionUtil.decryptCredential("encryptedCredential", base64Key)).thenReturn("{}");
        VCCredentialResponse vcResponse = VCCredentialResponse.builder().credential(VCCredentialProperties.builder().type(List.of(credentialType)).build()).build();
        when(objectMapper.readValue(anyString(), eq(VCCredentialResponse.class))).thenReturn(vcResponse);
        when(issuersService.getIssuerDetails(issuerId)).thenThrow(new ApiNotAccessibleException("API error"));

        CredentialProcessingException exception = assertThrows(CredentialProcessingException.class, () ->
                walletCredentialService.fetchVerifiableCredential(walletId, credentialId, base64Key, locale));

        assertEquals(CREDENTIAL_FETCH_EXCEPTION.getErrorCode(), exception.getErrorCode());
    }

    @Test
    public void shouldThrowCredentialProcessingExceptionOnPdfGenerationException() throws Exception {
        when(walletCredentialsRepository.findByIdAndWalletId(credentialId, walletId)).thenReturn(Optional.of(verifiableCredential));
        when(encryptionDecryptionUtil.decryptCredential("encryptedCredential", base64Key)).thenReturn("{}");
        VCCredentialResponse vcResponse = VCCredentialResponse.builder().credential(VCCredentialProperties.builder().type(List.of(credentialType)).build()).build();
        when(objectMapper.readValue(anyString(), eq(VCCredentialResponse.class))).thenReturn(vcResponse);
        when(issuersService.getIssuerDetails(issuerId)).thenReturn(new IssuerDTO());

        CredentialDefinitionResponseDto credentialDefinition = new CredentialDefinitionResponseDto();
        credentialDefinition.setType(List.of(credentialType));
        CredentialsSupportedResponse supportedResponse = new CredentialsSupportedResponse();
        supportedResponse.setCredentialDefinition(credentialDefinition);

        IssuerConfig issuerConfig = new IssuerConfig(new IssuerDTO(), new CredentialIssuerWellKnownResponse(), supportedResponse);
        when(issuersService.getIssuerConfig(issuerId, credentialType)).thenReturn(issuerConfig);

        when(credentialPDFGeneratorService.generatePdfForVerifiableCredentials(any(), any(), any(), any(), any(), any(), any()))
                .thenThrow(new RuntimeException("PDF error"));

        CredentialProcessingException exception = assertThrows(CredentialProcessingException.class, () ->
                walletCredentialService.fetchVerifiableCredential(walletId, credentialId, base64Key, locale));

        assertEquals(CREDENTIAL_FETCH_EXCEPTION.getErrorCode(), exception.getErrorCode());
    }
}