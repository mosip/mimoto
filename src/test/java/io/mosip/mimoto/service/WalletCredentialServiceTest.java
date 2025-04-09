package io.mosip.mimoto.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.kernel.cryptomanager.service.CryptomanagerService;
import io.mosip.mimoto.dbentity.VerifiableCredential;
import io.mosip.mimoto.dto.*;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.*;
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

import java.util.*;
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
    public void shouldNotThrowExceptionOnVerificationFailureDuringVCDownloaded() throws Exception {
        VCCredentialResponse vcResponse = new VCCredentialResponse();
        String encryptedCredential = "encryptedCredential";

        VerifiableCredential vc = getVerifiableCredential("vc-id-123", walletId, "encryptedCredential", issuerId, credentialType);
        VerifiableCredentialResponseDTO expectedVerifiableCredentialResponseDTO = getVerifiableCredentialResponseDTO("issuer name", "https://issuer_logo_url", credentialType, "https://logo", "vc-id-123");

        when(issuersService.getIssuerDetails(issuerId)).thenReturn(getMockIssuerDTO());
        when(issuersService.getIssuerConfiguration(issuerId)).thenReturn(issuerConfig);
        when(credentialUtilService.generateVCCredentialRequest(any(), any(), any(), eq(accessToken), eq(walletId), eq(base64Key), eq(true))).thenReturn(vcRequest);
        when(credentialUtilService.downloadCredential(anyString(), eq(vcRequest), eq(accessToken))).thenReturn(vcResponse);
        when(credentialUtilService.verifyCredential(any())).thenReturn(false);
        when(encryptionDecryptionUtil.encryptWithAES(any(), any())).thenReturn(encryptedCredential);
        when(walletCredentialsRepository.save(any())).thenReturn(vc);

        VerifiableCredentialResponseDTO actualVerifiableCredentialResponseDTO = walletCredentialService.fetchAndStoreCredential(
                issuerId, credentialType, tokenResponse, "1", "en", walletId, base64Key
        );

        ArgumentCaptor<VerifiableCredential> verifiableCredentialArgumentCaptor = ArgumentCaptor.forClass(VerifiableCredential.class);
        verify(walletCredentialsRepository).save(verifiableCredentialArgumentCaptor.capture());

        VerifiableCredential captureVerifiableCredential = verifiableCredentialArgumentCaptor.getValue();

        assertEquals(expectedVerifiableCredentialResponseDTO, actualVerifiableCredentialResponseDTO);
        assertEquals(false, captureVerifiableCredential.getCredentialMetadata().getIsVerified());
    }
}
