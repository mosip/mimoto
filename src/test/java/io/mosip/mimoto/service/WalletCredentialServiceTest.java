package io.mosip.mimoto.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.kernel.cryptomanager.service.CryptomanagerService;
import io.mosip.mimoto.dbentity.VerifiableCredential;
import io.mosip.mimoto.dto.*;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.dto.resident.WalletCredentialResponseDTO;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.repository.WalletCredentialsRepository;
import io.mosip.mimoto.service.impl.*;
import io.mosip.mimoto.util.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.client.RestTemplate;

import java.io.ByteArrayInputStream;
import java.util.*;

import static io.mosip.mimoto.exception.ErrorConstants.SIGNATURE_VERIFICATION_EXCEPTION;
import static io.mosip.mimoto.util.TestUtilities.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(SpringRunner.class)
public class WalletCredentialServiceTest {

    @InjectMocks
    private WalletCredentialServiceImpl walletCredentialService;

    @Mock
    private IssuersService issuersService;
    @Mock
    private DataShareServiceImpl dataShareService;
    @Mock
    private ObjectMapper objectMapper;
    @Mock
    private IdpService idpService;
    @Mock
    private RestTemplate restTemplate;
    @Mock
    private PresentationServiceImpl presentationService;
    @Mock
    private CryptomanagerService cryptomanagerService;
    @Mock
    private WalletCredentialsRepository walletCredentialsRepository;
    @Mock
    private CredentialUtilService credentialUtilService;
    @Mock
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    private final String walletId = "wallet123";
    private final String issuerId = "issuer123";
    private final String credentialType = "CredentialType1";
    private final String accessToken = "accessToken";
    private final String base64Key = Base64.getEncoder().encodeToString("dummykey12345678".getBytes());

    private CredentialIssuerConfiguration issuerConfig;
    private VCCredentialRequest vcRequest;
    TokenResponseDTO tokenResponse;

    @Before
    public void setUp() {
        walletCredentialService.init();
        issuerConfig = getCredentialIssuerConfigurationResponseDto(issuerId, credentialType, List.of());
        vcRequest = getVCCredentialRequestDTO();
        tokenResponse = new TokenResponseDTO();
        tokenResponse.setAccess_token(accessToken);
    }

    private IssuerDTO getMockIssuerDTO() {
        DisplayDTO display = new DisplayDTO();
        display.setName("issuer name");
        display.setDescription("issuer description");
        display.setLanguage("en");

        LogoDTO logoDTO = new LogoDTO();
        logoDTO.setUrl("https://issuer_logo_url");
        logoDTO.setAlt_text("issuerLogo");
        display.setLogo(logoDTO);

        IssuerDTO dto = new IssuerDTO();
        dto.setDisplay(List.of(display));
        dto.setIssuer_id(issuerId);
        return dto;
    }

    @Test
    public void shouldFetchAndStoreCredentialSuccessfully() throws Exception {
        VCCredentialResponse vcResponse = new VCCredentialResponse();
        String encryptedCredential = "encryptedCredential";

        VerifiableCredential vc = getVerifiableCredential("vc-id-123", walletId, "encryptedCredential", issuerId, credentialType);
        VerifiableCredentialResponseDTO expectedVerifiableCredentialResponseDTO = getVerifiableCredentialResponseDTO("issuer name", "https://issuer_logo_url", credentialType, "https://logo", "vc-id-123");

        when(issuersService.getIssuerDetails(issuerId)).thenReturn(getMockIssuerDTO());
        when(issuersService.getIssuerConfiguration(issuerId)).thenReturn(issuerConfig);
        when(credentialUtilService.generateVCCredentialRequest(any(), any(), any(), eq(accessToken), eq(walletId), eq(base64Key), eq(true))).thenReturn(vcRequest);
        when(credentialUtilService.downloadCredential(anyString(), eq(vcRequest), eq(accessToken))).thenReturn(vcResponse);
        when(credentialUtilService.verifyCredential(any())).thenReturn(true);
        when(encryptionDecryptionUtil.encryptWithAES(any(), any())).thenReturn(encryptedCredential);
        when(walletCredentialsRepository.save(any())).thenReturn(vc);

        VerifiableCredentialResponseDTO actualVerifiableCredentialResponseDTO = walletCredentialService.fetchAndStoreCredential(
                issuerId, credentialType, tokenResponse, "1", "en", walletId, base64Key
        );

        assertEquals(expectedVerifiableCredentialResponseDTO, actualVerifiableCredentialResponseDTO);
    }

    @Test
    public void shouldThrowExceptionWhenDuplicateCredentialExists() {
        when(walletCredentialsRepository.existsByIssuerIdAndCredentialTypeAndWalletId("Mosip", credentialType, walletId)).thenReturn(true);

        RuntimeException exception = assertThrows(RuntimeException.class, () ->
                walletCredentialService.fetchAndStoreCredential("Mosip", credentialType, tokenResponse, "1", "en", walletId, base64Key)
        );

        assertEquals("A credential is already downloaded for the selected Issuer and Credential Type. Only one is allowed, so download will not be initiated", exception.getMessage());
    }

    @Test
    public void shouldFetchAllCredentialsForWalletSuccessfully() throws Exception {
        VerifiableCredential vc = getVerifiableCredential("vc-id-123", walletId, "encryptedCredential", issuerId, credentialType);
        when(walletCredentialsRepository.findByWalletId(walletId)).thenReturn(List.of(vc));
        when(issuersService.getIssuerDetails(issuerId)).thenReturn(getMockIssuerDTO());
        when(issuersService.getIssuerConfiguration(issuerId)).thenReturn(issuerConfig);
        List<VerifiableCredentialResponseDTO> expectedCredentialsList = List.of(getVerifiableCredentialResponseDTO("issuer name", "https://issuer_logo_url", credentialType, "https://logo", "vc-id-123"));

        List<VerifiableCredentialResponseDTO> actualCredentialsList = walletCredentialService.fetchAllCredentialsForWallet(walletId, base64Key, "en");

        assertEquals(1, actualCredentialsList.size());
        assertEquals(expectedCredentialsList, actualCredentialsList);
    }

    @Test
    public void shouldIncludeEmptyCredentialDetailsInResponseIfAnyErrorOccurredWhileFetchingDetails() throws Exception {
        VerifiableCredential vc1 = getVerifiableCredential("vc-id-123", walletId, "encryptedCredential", issuerId, credentialType);
        VerifiableCredential vc2 = getVerifiableCredential("vc-id-124", walletId, "encryptedCredential", "issuer234", credentialType);
        when(walletCredentialsRepository.findByWalletId(walletId)).thenReturn(List.of(vc1, vc2));
        when(issuersService.getIssuerDetails(issuerId)).thenReturn(getMockIssuerDTO());
        when(issuersService.getIssuerDetails("issuer234")).thenThrow(new ApiNotAccessibleException());
        when(issuersService.getIssuerConfiguration(issuerId)).thenReturn(issuerConfig);
        List<VerifiableCredentialResponseDTO> expectedCredentialsList = List.of(getVerifiableCredentialResponseDTO("issuer name", "https://issuer_logo_url", credentialType, "https://logo", "vc-id-123"), getVerifiableCredentialResponseDTO("", "", "", "", "vc-id-124"));

        List<VerifiableCredentialResponseDTO> actualCredentialList = walletCredentialService.fetchAllCredentialsForWallet(walletId, base64Key, "en");

        assertEquals(2, actualCredentialList.size());
        assertEquals(expectedCredentialsList, actualCredentialList);
    }

    @Test
    public void shouldThrowExceptionOnVerificationFailureDuringVCDownloaded() throws Exception {
        VCCredentialResponse vcResponse = new VCCredentialResponse();
        String encryptedCredential = "encryptedCredential";
        VCVerificationException expectedException = new VCVerificationException(SIGNATURE_VERIFICATION_EXCEPTION.getErrorCode(),
                SIGNATURE_VERIFICATION_EXCEPTION.getErrorMessage());
        VerifiableCredential vc = getVerifiableCredential("vc-id-123", walletId, "encryptedCredential", issuerId, credentialType);

        when(issuersService.getIssuerDetails(issuerId)).thenReturn(getMockIssuerDTO());
        when(issuersService.getIssuerConfiguration(issuerId)).thenReturn(issuerConfig);
        when(credentialUtilService.generateVCCredentialRequest(any(), any(), any(), eq(accessToken), eq(walletId), eq(base64Key), eq(true))).thenReturn(vcRequest);
        when(credentialUtilService.downloadCredential(anyString(), eq(vcRequest), eq(accessToken))).thenReturn(vcResponse);
        when(credentialUtilService.verifyCredential(any())).thenReturn(false);
        when(encryptionDecryptionUtil.encryptWithAES(any(), any())).thenReturn(encryptedCredential);
        when(walletCredentialsRepository.save(any())).thenReturn(vc);

        VCVerificationException actualException = assertThrows(VCVerificationException.class, () -> walletCredentialService.fetchAndStoreCredential(
                issuerId, credentialType, tokenResponse, "1", "en", walletId, base64Key
        ));

        assertEquals(expectedException.getErrorCode(), actualException.getErrorCode());
        assertEquals(expectedException.getErrorText(), actualException.getErrorText());
    }

    @Test
    public void shouldFetchVerifiableCredentialSuccessfully() throws Exception {
        String credentialId = "cred123";
        String base64Key = Base64.getEncoder().encodeToString("dummykey12345678".getBytes());
        String locale = "en";
        String issuerId = "issuer123";
        String credentialType = "CredentialType1";
        String dataShareUrl = "https://datashare.url";
        String credentialValidity = "1";
        String encryptedCredential = "encryptedCredential";
        String decryptedCredential = "{\"credential\":\"test\"}";
        byte[] pdfBytes = "PDF Content".getBytes(); // Dummy PDF content
        ByteArrayInputStream inputStream = new ByteArrayInputStream(pdfBytes);

        VerifiableCredential verifiableCredential = getVerifiableCredential(credentialId, walletId, encryptedCredential, issuerId, credentialType);
        verifiableCredential.getCredentialMetadata().setDataShareUrl(dataShareUrl);
        verifiableCredential.getCredentialMetadata().setCredentialValidity(credentialValidity);

        VCCredentialResponse vcResponse = new VCCredentialResponse();
        CredentialIssuerConfiguration issuerConfig = getCredentialIssuerConfigurationResponseDto(issuerId, credentialType, List.of());

        // Create proper display objects
        CredentialSupportedDisplayResponse display = new CredentialSupportedDisplayResponse();
        display.setName(credentialType);
        display.setLocale(locale);

        CredentialsSupportedResponse credentialsSupportedResponse = new CredentialsSupportedResponse();
        credentialsSupportedResponse.setDisplay(List.of(display));

        // Create proper issuer well-known response
        CredentialIssuerWellKnownResponse wellKnownResponse = new CredentialIssuerWellKnownResponse();
        Map<String, CredentialsSupportedResponse> configs = new HashMap<>();
        configs.put(credentialType, credentialsSupportedResponse);
        wellKnownResponse.setCredentialConfigurationsSupported(configs);

        when(walletCredentialsRepository.findById(credentialId)).thenReturn(Optional.of(verifiableCredential));
        when(encryptionDecryptionUtil.decryptCredential(encryptedCredential, base64Key)).thenReturn(decryptedCredential);
        when(issuersService.getIssuerDetails(issuerId)).thenReturn(getMockIssuerDTO());
        when(issuersService.getIssuerConfiguration(issuerId)).thenReturn(issuerConfig);
        when(objectMapper.readValue(decryptedCredential, VCCredentialResponse.class)).thenReturn(vcResponse);
        when(credentialUtilService.generatePdfForVerifiableCredentials(
                anyString(), // credentialType
                any(VCCredentialResponse.class), // vcResponse
                any(IssuerDTO.class), // issuerDTO
                any(CredentialsSupportedResponse.class), // credentialsSupportedResponse
                anyString(), // dataShareUrl
                anyString(), // credentialValidity
                anyString()  // locale
        )).thenReturn(inputStream);

        WalletCredentialResponseDTO response = walletCredentialService.fetchVerifiableCredential(walletId, credentialId, base64Key, locale);

        assertNotNull(response);
        assertNotNull(response.getFileContentStream());
        assertEquals(credentialType, response.getFileName());
    }

    @Test
    public void shouldThrowExceptionWhenCredentialNotFound() {
        String credentialId = "nonExistentCredential";
        String base64Key = Base64.getEncoder().encodeToString("dummykey12345678".getBytes());
        String locale = "en";

        when(walletCredentialsRepository.findById(credentialId)).thenReturn(Optional.empty());

        RuntimeException exception = assertThrows(RuntimeException.class, () ->
                walletCredentialService.fetchVerifiableCredential(walletId, credentialId, base64Key, locale)
        );

        assertEquals("Credential not found", exception.getMessage());
    }

    @Test
    public void shouldThrowExceptionWhenDecryptionFails() throws Exception {
        String credentialId = "cred123";
        String base64Key = Base64.getEncoder().encodeToString("dummykey12345678".getBytes());
        String locale = "en";
        String encryptedCredential = "encryptedCredential";

        VerifiableCredential verifiableCredential = getVerifiableCredential(credentialId, walletId, encryptedCredential, issuerId, credentialType);

        when(walletCredentialsRepository.findById(credentialId)).thenReturn(Optional.of(verifiableCredential));
        when(encryptionDecryptionUtil.decryptCredential(encryptedCredential, base64Key))
                .thenThrow(new RuntimeException("Decryption failed"));

        RuntimeException exception = assertThrows(RuntimeException.class, () ->
                walletCredentialService.fetchVerifiableCredential(walletId, credentialId, base64Key, locale)
        );

        assertEquals("Decryption failed", exception.getMessage());
    }

    @Test
    public void shouldThrowExceptionWhenIssuerConfigurationRetrievalFails() throws Exception {
        String credentialId = "cred123";
        String base64Key = Base64.getEncoder().encodeToString("dummykey12345678".getBytes());
        String locale = "en";
        String encryptedCredential = "encryptedCredential";
        String decryptedCredential = "{\"credential\":\"test\"}";

        VerifiableCredential verifiableCredential = getVerifiableCredential(credentialId, walletId, encryptedCredential, issuerId, credentialType);

        when(walletCredentialsRepository.findById(credentialId)).thenReturn(Optional.of(verifiableCredential));
        when(encryptionDecryptionUtil.decryptCredential(encryptedCredential, base64Key)).thenReturn(decryptedCredential);
        when(issuersService.getIssuerDetails(issuerId)).thenThrow(new ApiNotAccessibleException());

        ApiNotAccessibleException exception = assertThrows(ApiNotAccessibleException.class, () ->
                walletCredentialService.fetchVerifiableCredential(walletId, credentialId, base64Key, locale)
        );

        assertNotNull(exception);
    }

    @Test
    public void shouldThrowExceptionWhenPdfGenerationFails() throws Exception {
        String credentialId = "cred123";
        String base64Key = Base64.getEncoder().encodeToString("dummykey12345678".getBytes());
        String locale = "en";
        String encryptedCredential = "encryptedCredential";
        String decryptedCredential = "{\"credential\":\"test\"}";
        String issuerId = "issuer123";
        String credentialType = "CredentialType1";
        String dataShareUrl = "https://datashare.url";
        String credentialValidity = "1";

        VerifiableCredential verifiableCredential = getVerifiableCredential(credentialId, walletId, encryptedCredential, issuerId, credentialType);
        verifiableCredential.getCredentialMetadata().setDataShareUrl(dataShareUrl);
        verifiableCredential.getCredentialMetadata().setCredentialValidity(credentialValidity);

        VCCredentialResponse vcResponse = new VCCredentialResponse();
        CredentialIssuerConfiguration issuerConfig = getCredentialIssuerConfigurationResponseDto(issuerId, credentialType, List.of());

        when(walletCredentialsRepository.findById(credentialId)).thenReturn(Optional.of(verifiableCredential));
        when(encryptionDecryptionUtil.decryptCredential(encryptedCredential, base64Key)).thenReturn(decryptedCredential);
        when(issuersService.getIssuerDetails(issuerId)).thenReturn(getMockIssuerDTO());
        when(issuersService.getIssuerConfiguration(issuerId)).thenReturn(issuerConfig);
        when(objectMapper.readValue(decryptedCredential, VCCredentialResponse.class)).thenReturn(vcResponse);
        when(credentialUtilService.generatePdfForVerifiableCredentials(
                anyString(), // credentialType
                any(VCCredentialResponse.class), // vcCredentialResponse
                any(IssuerDTO.class), // issuerDTO
                any(CredentialsSupportedResponse.class), // credentialsSupportedResponse
                anyString(), // dataShareUrl
                anyString(), // credentialValidity
                anyString()  // locale
        )).thenThrow(new RuntimeException("PDF generation failed"));

        RuntimeException exception = assertThrows(RuntimeException.class, () ->
                walletCredentialService.fetchVerifiableCredential(walletId, credentialId, base64Key, locale)
        );

        assertEquals("PDF generation failed", exception.getMessage());
    }
}
