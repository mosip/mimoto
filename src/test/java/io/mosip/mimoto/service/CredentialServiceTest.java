package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.exception.VCVerificationException;
import io.mosip.mimoto.model.QRCodeType;
import io.mosip.mimoto.model.VerifiableCredential;
import io.mosip.mimoto.service.impl.CredentialServiceImpl;
import io.mosip.mimoto.service.impl.IssuersServiceImpl;
import io.mosip.mimoto.util.RestApiClient;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpEntity;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import io.mosip.mimoto.exception.InvalidCredentialResourceException;
import io.mosip.mimoto.dto.mimoto.VCCredentialRequest;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import static org.mockito.Mockito.mock;
import io.mosip.mimoto.repository.WalletCredentialsRepository;
import io.mosip.mimoto.dto.mimoto.IssuerConfig;
import io.mosip.mimoto.dto.mimoto.VerifiableCredentialResponseDTO;
import io.mosip.mimoto.util.EncryptionDecryptionUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import static io.mosip.mimoto.exception.ErrorConstants.INVALID_REQUEST;
import io.mosip.mimoto.exception.CredentialProcessingException;
import static io.mosip.mimoto.exception.ErrorConstants.CREDENTIAL_DOWNLOAD_EXCEPTION;
import io.mosip.mimoto.exception.ExternalServiceUnavailableException;
import static io.mosip.mimoto.exception.ErrorConstants.SERVER_UNAVAILABLE;
import com.fasterxml.jackson.core.JsonProcessingException;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static io.mosip.mimoto.exception.ErrorConstants.SIGNATURE_VERIFICATION_EXCEPTION;
import static io.mosip.mimoto.util.TestUtilities.*;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
@SpringBootTest
public class CredentialServiceTest {

    @Mock
    CredentialRequestService credentialRequestService;

    @Mock
    CredentialVerifierService credentialVerifierService;

    @Mock
    RestApiClient restApiClient;

    @InjectMocks
    CredentialServiceImpl credentialService;

    @Mock
    CredentialPDFGeneratorService credentialUtilService;

    @Mock
    IssuersServiceImpl issuersService;

    @Mock
    WalletCredentialsRepository walletCredentialsRepository;

    @Mock
    EncryptionDecryptionUtil encryptionDecryptionUtil;

    @Mock
    ObjectMapper objectMapper;

    TokenResponseDTO expectedTokenResponse;
    String tokenEndpoint, issuerId;
    IssuerDTO issuerDTO;
    HttpEntity<MultiValueMap<String, String>> mockRequest;
    CredentialIssuerConfiguration issuerConfig;

    @Before
    public void setUp() throws Exception {
        issuerId = "issuer1";
        issuerDTO = getIssuerConfigDTO(issuerId);
        issuerConfig = getCredentialIssuerConfigurationResponseDto(issuerId, "CredentialType1", List.of());

        Mockito.when(issuersService.getIssuerDetails(issuerId)).thenReturn(issuerDTO);
        Mockito.when(issuersService.getIssuerConfiguration(issuerId)).thenReturn(issuerConfig);

        tokenEndpoint = issuerConfig.getAuthorizationServerWellKnownResponse().getTokenEndpoint();
        mockRequest = new HttpEntity<>(new LinkedMultiValueMap<>(Map.of(
                "grant_type", List.of("client_credentials"),
                "client_id", List.of("test-client")
        )));
        expectedTokenResponse = getTokenResponseDTO();
    }

    @Test
    public void shouldParseHtmlStringToDocument() {
        String htmlContent = "<html><body><h1>$message</h1></body></html>";
        Map<String, Object> data = new HashMap<>();
        data.put("message", "PDF");
        VelocityContext velocityContext = new VelocityContext();
        StringWriter writer = new StringWriter();
        velocityContext.put("message", data.get("message"));
        Velocity.evaluate(velocityContext, writer, "Credential Template", htmlContent);
        String mergedHtml = writer.toString();
        assertTrue(mergedHtml.contains("PDF"));
    }

    @Test
    public void shouldThrowExceptionIfDownloadedVCSignatureVerificationFailed() throws Exception {
        Mockito.when(issuersService.getIssuerDetails(issuerId)).thenReturn(issuerDTO);
        Mockito.when(issuersService.getIssuerConfiguration(issuerId)).thenReturn(issuerConfig);
        when(credentialRequestService.buildRequest(any(IssuerDTO.class),
                any(String.class),
                any(CredentialIssuerWellKnownResponse.class),
                any(String.class), any(), any(), eq(false))).thenReturn(getVCCredentialRequestDTO());
        VerifiableCredentialResponse vcCredentialResponse = getVerifiableCredentialResponseDTO("CredentialType1");
        when(restApiClient.postApi(
                any(String.class),
                any(MediaType.class),
                any(VCCredentialRequest.class),
                eq(VerifiableCredentialResponse.class),
                any(String.class)
        )).thenReturn(vcCredentialResponse);
        when(credentialVerifierService.verify(any(VCCredentialResponse.class))).thenReturn(false);
        VCVerificationException actualException = assertThrows(VCVerificationException.class, () ->
                credentialService.downloadCredentialAsPDF(issuerId, "CredentialType1", expectedTokenResponse, "once", "en"));

        assertEquals("signature_verification_failed --> Error while doing signature verification", actualException.getMessage());
    }

    @Test
    public void shouldReturnDownloadedVCAsPDFIfSignatureVerificationIsSuccessful() throws Exception {
        Mockito.when(issuersService.getIssuerDetails(issuerId)).thenReturn(issuerDTO);
        Mockito.when(issuersService.getIssuerConfiguration(issuerId)).thenReturn(issuerConfig);
        when(credentialRequestService.buildRequest(any(IssuerDTO.class),
                any(String.class),
                any(CredentialIssuerWellKnownResponse.class),
                any(String.class), any(), any(), eq(false))).thenReturn(getVCCredentialRequestDTO());
        VerifiableCredentialResponse vcCredentialResponse = getVerifiableCredentialResponseDTO("CredentialType1");
        when(restApiClient.postApi(
                any(String.class),
                any(MediaType.class),
                any(VCCredentialRequest.class),
                eq(VerifiableCredentialResponse.class),
                any(String.class)
        )).thenReturn(vcCredentialResponse);
        when(credentialVerifierService.verify(any(VCCredentialResponse.class))).thenReturn(true);
        issuerDTO.setQr_code_type(QRCodeType.None);

        ByteArrayInputStream expectedPDFByteArray = generatePdfFromHTML();
        Mockito.when(credentialUtilService.generatePdfForVerifiableCredential(
                eq("CredentialType1"),
                any(VCCredentialResponse.class),
                eq(issuerDTO),
                eq(issuerConfig.getCredentialConfigurationsSupported().get("CredentialType1")),
                eq(""),
                eq("once"),
                eq("en")
        )).thenReturn(expectedPDFByteArray);

        ByteArrayInputStream actualPDFByteArray =
                credentialService.downloadCredentialAsPDF(issuerId, "CredentialType1", expectedTokenResponse, "once", "en");

        assertEquals(expectedPDFByteArray, actualPDFByteArray);
    }

    @Test
    public void shouldReturnVCCredentialResponseWhenDownloadCredentialIsSuccessful() throws Exception {
        String credentialEndpoint = "https://example.com/credential";
        VCCredentialRequest vcCredentialRequest = getVCCredentialRequestDTO();
        String accessToken = "valid-access-token";

        VerifiableCredentialResponse mockResponse = getVerifiableCredentialResponseDTO("CredentialType1");

        when(restApiClient.postApi(
                eq(credentialEndpoint),
                eq(MediaType.APPLICATION_JSON),
                eq(vcCredentialRequest),
                eq(VerifiableCredentialResponse.class),
                eq(accessToken)
        )).thenReturn(mockResponse);

        VCCredentialResponse result = credentialService.downloadCredential(
                credentialEndpoint, vcCredentialRequest, accessToken);

        assertNotNull(result);
        assertEquals(vcCredentialRequest.getFormat(), result.getFormat());
        assertEquals(mockResponse.getCredential(), result.getCredential());
    }

    @Test
    public void shouldThrowInvalidCredentialResourceExceptionWhenRestApiReturnsNull() {
        String credentialEndpoint = "https://example.com/credential";
        VCCredentialRequest vcCredentialRequest = getVCCredentialRequestDTO();
        String accessToken = "valid-access-token";

        when(restApiClient.postApi(
                eq(credentialEndpoint),
                eq(MediaType.APPLICATION_JSON),
                eq(vcCredentialRequest),
                eq(VerifiableCredentialResponse.class),
                eq(accessToken)
        )).thenReturn(null);

        InvalidCredentialResourceException exception = assertThrows(
                InvalidCredentialResourceException.class,
                () -> credentialService.downloadCredential(credentialEndpoint, vcCredentialRequest, accessToken)
        );

        assertTrue(exception.getMessage().contains("VC Credential Issue API not accessible"));
    }

    @Test
    public void shouldDownloadCredentialAndStoreInDBSuccessfully() throws Exception {
        // Setup test data
        TokenResponseDTO tokenResponse = getTokenResponseDTO();
        String credentialConfigurationId = "CredentialType1";
        String walletId = "wallet123";
        String base64Key = "testKey123";
        String issuerId = "issuer1";
        String locale = "en";

        // Mock dependencies
        IssuerConfig issuerConfig = mock(IssuerConfig.class);
        IssuerDTO mockIssuerDTO = getIssuerConfigDTO(issuerId);
        CredentialIssuerWellKnownResponse mockWellKnownResponse = new CredentialIssuerWellKnownResponse();
        mockWellKnownResponse.setCredentialEndPoint("https://example.com/credential");

        VCCredentialRequest vcCredentialRequest = getVCCredentialRequestDTO();
        VerifiableCredential savedCredential = new VerifiableCredential();
        savedCredential.setId("credential-id-123");

        // Setup issuer config mocks
        when(issuerConfig.getIssuerDTO()).thenReturn(mockIssuerDTO);
        when(issuerConfig.getWellKnownResponse()).thenReturn(mockWellKnownResponse);

        // Mock service calls
        when(issuersService.getIssuerConfig(issuerId, credentialConfigurationId)).thenReturn(issuerConfig);
        when(credentialRequestService.buildRequest(any(), eq(credentialConfigurationId), any(), any(), eq(walletId), eq(base64Key), eq(true)))
                .thenReturn(vcCredentialRequest);
        when(restApiClient.postApi(any(), any(), eq(vcCredentialRequest), eq(VerifiableCredentialResponse.class), any()))
                .thenReturn(getVerifiableCredentialResponseDTO(credentialConfigurationId));
        when(credentialVerifierService.verify(any(VCCredentialResponse.class))).thenReturn(true);
        when(objectMapper.writeValueAsString(any())).thenReturn("{\"credential\":\"data\"}");
        when(encryptionDecryptionUtil.encryptCredential(any(), eq(base64Key))).thenReturn("encrypted-credential");
        when(walletCredentialsRepository.save(any(VerifiableCredential.class))).thenReturn(savedCredential);

        // Execute
        VerifiableCredentialResponseDTO result = credentialService.downloadCredentialAndStoreInDB(
                tokenResponse, credentialConfigurationId, walletId, base64Key, issuerId, locale);

        // Verify
        assertNotNull(result);
        assertEquals("credential-id-123", result.getCredentialId());
    }

    @Test
    public void shouldThrowVCVerificationExceptionWhenVerificationFails() throws Exception {
        // Setup test data
        TokenResponseDTO tokenResponse = getTokenResponseDTO();
        String credentialConfigurationId = "CredentialType1";
        String walletId = "wallet123";
        String base64Key = "testKey123";
        String issuerId = "issuer1";
        String locale = "en";

        // Mock dependencies
        IssuerConfig issuerConfig = mock(IssuerConfig.class);
        IssuerDTO mockIssuerDTO = getIssuerConfigDTO(issuerId);
        CredentialIssuerWellKnownResponse mockWellKnownResponse = new CredentialIssuerWellKnownResponse();
        mockWellKnownResponse.setCredentialEndPoint("https://example.com/credential");

        // Setup issuer config mocks
        when(issuerConfig.getIssuerDTO()).thenReturn(mockIssuerDTO);
        when(issuerConfig.getWellKnownResponse()).thenReturn(mockWellKnownResponse);

        // Mock service calls
        when(issuersService.getIssuerConfig(issuerId, credentialConfigurationId)).thenReturn(issuerConfig);
        when(credentialRequestService.buildRequest(any(), any(), any(), any(), any(), any(), eq(true)))
                .thenReturn(getVCCredentialRequestDTO());
        when(restApiClient.postApi(any(), any(), any(), eq(VerifiableCredentialResponse.class), any()))
                .thenReturn(getVerifiableCredentialResponseDTO(credentialConfigurationId));
        when(credentialVerifierService.verify(any())).thenReturn(false);

        // Execute and verify exception
        VCVerificationException exception = assertThrows(VCVerificationException.class, () ->
                credentialService.downloadCredentialAndStoreInDB(tokenResponse, credentialConfigurationId, walletId, base64Key, issuerId, locale));

        assertEquals(SIGNATURE_VERIFICATION_EXCEPTION.getErrorCode(), exception.getErrorCode());
    }

    @Test
    public void shouldThrowInvalidRequestExceptionForNullTokenResponse() {
        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                credentialService.downloadCredentialAndStoreInDB(
                        null, "CredentialType1", "wallet123", "testKey123", "issuer1", "en"));

        assertEquals(INVALID_REQUEST.getErrorCode(), exception.getErrorCode());
        assertTrue(exception.getMessage().contains("Token response or access token cannot be null"));
    }

    @Test
    public void shouldThrowInvalidRequestExceptionForBlankAccessToken() {
        TokenResponseDTO tokenResponse = new TokenResponseDTO();
        tokenResponse.setAccess_token(""); // blank token

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                credentialService.downloadCredentialAndStoreInDB(
                        tokenResponse, "CredentialType1", "wallet123", "testKey123", "issuer1", "en"));

        assertEquals(INVALID_REQUEST.getErrorCode(), exception.getErrorCode());
        assertTrue(exception.getMessage().contains("Token response or access token cannot be null"));
    }

    @Test
    public void shouldThrowInvalidRequestExceptionForBlankCredentialConfigurationId() {
        TokenResponseDTO tokenResponse = getTokenResponseDTO();

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                credentialService.downloadCredentialAndStoreInDB(
                        tokenResponse, "", "wallet123", "testKey123", "issuer1", "en"));

        assertEquals(INVALID_REQUEST.getErrorCode(), exception.getErrorCode());
        assertTrue(exception.getMessage().contains("Credential configuration id cannot be null or blank"));
    }

    @Test
    public void shouldThrowInvalidRequestExceptionForBlankWalletId() {
        TokenResponseDTO tokenResponse = getTokenResponseDTO();

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                credentialService.downloadCredentialAndStoreInDB(
                        tokenResponse, "CredentialType1", "", "testKey123", "issuer1", "en"));

        assertEquals(INVALID_REQUEST.getErrorCode(), exception.getErrorCode());
        assertTrue(exception.getMessage().contains("Wallet ID cannot be null or blank"));
    }

    @Test
    public void shouldThrowInvalidRequestExceptionForBlankBase64Key() {
        TokenResponseDTO tokenResponse = getTokenResponseDTO();

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                credentialService.downloadCredentialAndStoreInDB(
                        tokenResponse, "CredentialType1", "wallet123", "", "issuer1", "en"));

        assertEquals(INVALID_REQUEST.getErrorCode(), exception.getErrorCode());
        assertTrue(exception.getMessage().contains("Wallet key cannot be null or blank"));
    }

    @Test
    public void shouldThrowInvalidRequestExceptionForBlankIssuerId() {
        TokenResponseDTO tokenResponse = getTokenResponseDTO();

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                credentialService.downloadCredentialAndStoreInDB(
                        tokenResponse, "CredentialType1", "wallet123", "testKey123", "", "en"));

        assertEquals(INVALID_REQUEST.getErrorCode(), exception.getErrorCode());
        assertTrue(exception.getMessage().contains("Issuer ID cannot be null or blank"));
    }

    @Test
    public void shouldThrowCredentialProcessingExceptionWhenFetchIssuerConfigFails() throws Exception {
        TokenResponseDTO tokenResponse = getTokenResponseDTO();
        String credentialConfigurationId = "CredentialType1";
        String walletId = "wallet123";
        String base64Key = "testKey123";
        String issuerId = "issuer1";
        String locale = "en";

        // Mock issuersService to throw exception
        when(issuersService.getIssuerConfig(issuerId, credentialConfigurationId))
                .thenThrow(new RuntimeException("Issuer service unavailable"));

        // Execute and verify exception
        CredentialProcessingException exception = assertThrows(CredentialProcessingException.class, () ->
                credentialService.downloadCredentialAndStoreInDB(
                        tokenResponse, credentialConfigurationId, walletId, base64Key, issuerId, locale));

        assertEquals(CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(), exception.getErrorCode());
        assertTrue(exception.getMessage().contains("Unable to fetch issuer configuration"));
    }

    @Test
    public void shouldThrowCredentialProcessingExceptionWhenBuildCredentialRequestFails() throws Exception {
        TokenResponseDTO tokenResponse = getTokenResponseDTO();
        String credentialConfigurationId = "CredentialType1";
        String walletId = "wallet123";
        String base64Key = "testKey123";
        String issuerId = "issuer1";
        String locale = "en";

        // Mock dependencies for success until buildRequest
        IssuerConfig issuerConfig = mock(IssuerConfig.class);
        IssuerDTO mockIssuerDTO = getIssuerConfigDTO(issuerId);
        CredentialIssuerWellKnownResponse mockWellKnownResponse = new CredentialIssuerWellKnownResponse();

        when(issuerConfig.getIssuerDTO()).thenReturn(mockIssuerDTO);
        when(issuerConfig.getWellKnownResponse()).thenReturn(mockWellKnownResponse);
        when(issuersService.getIssuerConfig(issuerId, credentialConfigurationId)).thenReturn(issuerConfig);

        // Mock credentialRequestService to throw exception
        when(credentialRequestService.buildRequest(any(), eq(credentialConfigurationId), any(), any(), eq(walletId), eq(base64Key), eq(true)))
                .thenThrow(new RuntimeException("Failed to build credential request"));

        // Execute and verify exception
        CredentialProcessingException exception = assertThrows(CredentialProcessingException.class, () ->
                credentialService.downloadCredentialAndStoreInDB(
                        tokenResponse, credentialConfigurationId, walletId, base64Key, issuerId, locale));

        assertEquals(CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(), exception.getErrorCode());
        assertTrue(exception.getMessage().contains("Unable to generate credential request"));
    }

    @Test
    public void shouldThrowExternalServiceUnavailableExceptionWhenDownloadCredentialFromIssuerFails() throws Exception {
        TokenResponseDTO tokenResponse = getTokenResponseDTO();
        String credentialConfigurationId = "CredentialType1";
        String walletId = "wallet123";
        String base64Key = "testKey123";
        String issuerId = "issuer1";
        String locale = "en";

        // Mock dependencies for success until downloadCredential
        IssuerConfig issuerConfig = mock(IssuerConfig.class);
        IssuerDTO mockIssuerDTO = getIssuerConfigDTO(issuerId);
        CredentialIssuerWellKnownResponse mockWellKnownResponse = new CredentialIssuerWellKnownResponse();
        mockWellKnownResponse.setCredentialEndPoint("https://example.com/credential");

        when(issuerConfig.getIssuerDTO()).thenReturn(mockIssuerDTO);
        when(issuerConfig.getWellKnownResponse()).thenReturn(mockWellKnownResponse);
        when(issuersService.getIssuerConfig(issuerId, credentialConfigurationId)).thenReturn(issuerConfig);
        when(credentialRequestService.buildRequest(any(), any(), any(), any(), any(), any(), eq(true)))
                .thenReturn(getVCCredentialRequestDTO());

        // Mock restApiClient to throw exception during credential download
        when(restApiClient.postApi(any(), any(), any(), eq(VerifiableCredentialResponse.class), any()))
                .thenThrow(new RuntimeException("Network timeout"));

        // Execute and verify exception
        ExternalServiceUnavailableException exception = assertThrows(ExternalServiceUnavailableException.class, () ->
                credentialService.downloadCredentialAndStoreInDB(
                        tokenResponse, credentialConfigurationId, walletId, base64Key, issuerId, locale));

        assertEquals(SERVER_UNAVAILABLE.getErrorCode(), exception.getErrorCode());
        assertTrue(exception.getMessage().contains("Unable to download credential from issuer"));
    }

    @Test
    public void shouldThrowVCVerificationExceptionWhenCredentialVerifierServiceThrowsException() throws Exception {
        TokenResponseDTO tokenResponse = getTokenResponseDTO();
        String credentialConfigurationId = "CredentialType1";
        String walletId = "wallet123";
        String base64Key = "testKey123";
        String issuerId = "issuer1";
        String locale = "en";

        // Mock dependencies for success until verify
        IssuerConfig issuerConfig = mock(IssuerConfig.class);
        IssuerDTO mockIssuerDTO = getIssuerConfigDTO(issuerId);
        CredentialIssuerWellKnownResponse mockWellKnownResponse = new CredentialIssuerWellKnownResponse();
        mockWellKnownResponse.setCredentialEndPoint("https://example.com/credential");

        when(issuerConfig.getIssuerDTO()).thenReturn(mockIssuerDTO);
        when(issuerConfig.getWellKnownResponse()).thenReturn(mockWellKnownResponse);
        when(issuersService.getIssuerConfig(issuerId, credentialConfigurationId)).thenReturn(issuerConfig);
        when(credentialRequestService.buildRequest(any(), any(), any(), any(), any(), any(), eq(true)))
                .thenReturn(getVCCredentialRequestDTO());
        when(restApiClient.postApi(any(), any(), any(), eq(VerifiableCredentialResponse.class), any()))
                .thenReturn(getVerifiableCredentialResponseDTO(credentialConfigurationId));

        // Mock credentialVerifierService to throw exception
        when(credentialVerifierService.verify(any(VCCredentialResponse.class)))
                .thenThrow(new JsonProcessingException("JSON processing failed") {});

        // Execute and verify exception
        VCVerificationException exception = assertThrows(VCVerificationException.class, () ->
                credentialService.downloadCredentialAndStoreInDB(
                        tokenResponse, credentialConfigurationId, walletId, base64Key, issuerId, locale));

        assertEquals(SIGNATURE_VERIFICATION_EXCEPTION.getErrorCode(), exception.getErrorCode());
        assertTrue(exception.getMessage().contains("Credential verification failed"));
    }

    @Test
    public void shouldThrowCredentialProcessingExceptionWhenSerializationFails() throws Exception {
        TokenResponseDTO tokenResponse = getTokenResponseDTO();
        String credentialConfigurationId = "CredentialType1";
        String walletId = "wallet123";
        String base64Key = "testKey123";
        String issuerId = "issuer1";
        String locale = "en";

        // Mock dependencies for success until serialization
        IssuerConfig issuerConfig = mock(IssuerConfig.class);
        IssuerDTO mockIssuerDTO = getIssuerConfigDTO(issuerId);
        CredentialIssuerWellKnownResponse mockWellKnownResponse = new CredentialIssuerWellKnownResponse();
        mockWellKnownResponse.setCredentialEndPoint("https://example.com/credential");

        when(issuerConfig.getIssuerDTO()).thenReturn(mockIssuerDTO);
        when(issuerConfig.getWellKnownResponse()).thenReturn(mockWellKnownResponse);
        when(issuersService.getIssuerConfig(issuerId, credentialConfigurationId)).thenReturn(issuerConfig);
        when(credentialRequestService.buildRequest(any(), any(), any(), any(), any(), any(), eq(true)))
                .thenReturn(getVCCredentialRequestDTO());
        when(restApiClient.postApi(any(), any(), any(), eq(VerifiableCredentialResponse.class), any()))
                .thenReturn(getVerifiableCredentialResponseDTO(credentialConfigurationId));
        when(credentialVerifierService.verify(any(VCCredentialResponse.class))).thenReturn(true);

        // Mock objectMapper to throw JsonProcessingException
        when(objectMapper.writeValueAsString(any()))
                .thenThrow(new JsonProcessingException("Serialization failed") {});

        // Execute and verify exception
        CredentialProcessingException exception = assertThrows(CredentialProcessingException.class, () ->
                credentialService.downloadCredentialAndStoreInDB(
                        tokenResponse, credentialConfigurationId, walletId, base64Key, issuerId, locale));

        assertEquals(CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(), exception.getErrorCode());
        assertTrue(exception.getMessage().contains("Unable to serialize credential response"));
    }

    @Test
    public void shouldThrowCredentialProcessingExceptionWhenEncryptionFails() throws Exception {
        TokenResponseDTO tokenResponse = getTokenResponseDTO();
        String credentialConfigurationId = "CredentialType1";
        String walletId = "wallet123";
        String base64Key = "testKey123";
        String issuerId = "issuer1";
        String locale = "en";

        // Mock dependencies for success until encryption
        IssuerConfig issuerConfig = mock(IssuerConfig.class);
        IssuerDTO mockIssuerDTO = getIssuerConfigDTO(issuerId);
        CredentialIssuerWellKnownResponse mockWellKnownResponse = new CredentialIssuerWellKnownResponse();
        mockWellKnownResponse.setCredentialEndPoint("https://example.com/credential");

        when(issuerConfig.getIssuerDTO()).thenReturn(mockIssuerDTO);
        when(issuerConfig.getWellKnownResponse()).thenReturn(mockWellKnownResponse);
        when(issuersService.getIssuerConfig(issuerId, credentialConfigurationId)).thenReturn(issuerConfig);
        when(credentialRequestService.buildRequest(any(), any(), any(), any(), any(), any(), eq(true)))
                .thenReturn(getVCCredentialRequestDTO());
        when(restApiClient.postApi(any(), any(), any(), eq(VerifiableCredentialResponse.class), any()))
                .thenReturn(getVerifiableCredentialResponseDTO(credentialConfigurationId));
        when(credentialVerifierService.verify(any(VCCredentialResponse.class))).thenReturn(true);
        when(objectMapper.writeValueAsString(any())).thenReturn("{\"credential\":\"data\"}");

        // Mock encryptionDecryptionUtil to throw exception
        when(encryptionDecryptionUtil.encryptCredential(any(), eq(base64Key)))
                .thenThrow(new RuntimeException("Encryption failed"));

        // Execute and verify exception
        CredentialProcessingException exception = assertThrows(CredentialProcessingException.class, () ->
                credentialService.downloadCredentialAndStoreInDB(
                        tokenResponse, credentialConfigurationId, walletId, base64Key, issuerId, locale));

        assertEquals(CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(), exception.getErrorCode());
        assertTrue(exception.getMessage().contains("Unable to encrypt credential data"));
    }

    @Test
    public void shouldThrowCredentialProcessingExceptionWhenSaveCredentialFails() throws Exception {
        TokenResponseDTO tokenResponse = getTokenResponseDTO();
        String credentialConfigurationId = "CredentialType1";
        String walletId = "wallet123";
        String base64Key = "testKey123";
        String issuerId = "issuer1";
        String locale = "en";

        // Mock dependencies for success until save
        IssuerConfig issuerConfig = mock(IssuerConfig.class);
        IssuerDTO mockIssuerDTO = getIssuerConfigDTO(issuerId);
        CredentialIssuerWellKnownResponse mockWellKnownResponse = new CredentialIssuerWellKnownResponse();
        mockWellKnownResponse.setCredentialEndPoint("https://example.com/credential");

        when(issuerConfig.getIssuerDTO()).thenReturn(mockIssuerDTO);
        when(issuerConfig.getWellKnownResponse()).thenReturn(mockWellKnownResponse);
        when(issuersService.getIssuerConfig(issuerId, credentialConfigurationId)).thenReturn(issuerConfig);
        when(credentialRequestService.buildRequest(any(), any(), any(), any(), any(), any(), eq(true)))
                .thenReturn(getVCCredentialRequestDTO());
        when(restApiClient.postApi(any(), any(), any(), eq(VerifiableCredentialResponse.class), any()))
                .thenReturn(getVerifiableCredentialResponseDTO(credentialConfigurationId));
        when(credentialVerifierService.verify(any(VCCredentialResponse.class))).thenReturn(true);
        when(objectMapper.writeValueAsString(any())).thenReturn("{\"credential\":\"data\"}");
        when(encryptionDecryptionUtil.encryptCredential(any(), eq(base64Key))).thenReturn("encrypted-credential");

        // Mock walletCredentialsRepository to throw exception
        when(walletCredentialsRepository.save(any(VerifiableCredential.class)))
                .thenThrow(new RuntimeException("Database connection failed"));

        // Execute and verify exception
        CredentialProcessingException exception = assertThrows(CredentialProcessingException.class, () ->
                credentialService.downloadCredentialAndStoreInDB(
                        tokenResponse, credentialConfigurationId, walletId, base64Key, issuerId, locale));

        assertEquals(CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(), exception.getErrorCode());
        assertTrue(exception.getMessage().contains("Unable to save credential to database"));
    }
}
