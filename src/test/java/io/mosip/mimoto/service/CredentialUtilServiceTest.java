package io.mosip.mimoto.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.exception.VCVerificationException;
import io.mosip.mimoto.model.QRCodeType;
import io.mosip.mimoto.service.impl.IssuersServiceImpl;
import io.mosip.mimoto.util.*;
import io.mosip.vercred.vcverifier.CredentialsVerifier;
import io.mosip.vercred.vcverifier.constants.CredentialFormat;
import io.mosip.vercred.vcverifier.data.VerificationResult;
import lombok.extern.slf4j.Slf4j;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;

import java.io.ByteArrayInputStream;
import java.util.List;
import java.util.Map;

import static io.mosip.mimoto.util.TestUtilities.*;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;

@RunWith(MockitoJUnitRunner.class)
@SpringBootTest
@Slf4j
public class CredentialUtilServiceTest {
    @InjectMocks
    CredentialUtilService credentialUtilService;

    @Mock
    IssuersServiceImpl issuersService;

    @Mock
    RestApiClient restApiClient;
    @Mock
    JoseUtil joseUtil;
    @Mock
    CredentialsVerifier credentialsVerifier;
    @Mock
    ObjectMapper objectMapper;

    @Mock
    Utilities utilities;

    IssuerDTO issuerDTO;

    CredentialIssuerConfiguration issuerConfig;

    String expectedExceptionMsg, issuerId;



    @Before
    public void setUp() throws Exception {
        issuerId = "issuer1";
        issuerDTO = getIssuerConfigDTO(issuerId);
        issuerConfig = getCredentialIssuerConfigurationResponseDto(issuerId, "CredentialType1", List.of());
    }

    @Test
    public void shouldThrowExceptionOnFetchingCredentialFromCredentialEndpointFailure() {
        CredentialsSupportedResponse credentialsSupportedResponse = getCredentialSupportedResponse("CredentialType1");
        CredentialIssuerWellKnownResponse issuerWellKnownResponse = getCredentialIssuerWellKnownResponseDto(issuerId, Map.of("CredentialType1", credentialsSupportedResponse));
        VCCredentialRequest vcCredentialRequest = getVCCredentialRequestDTO();
        Mockito.when(restApiClient.postApi(issuerWellKnownResponse.getCredentialEndPoint(), MediaType.APPLICATION_JSON, vcCredentialRequest, VCCredentialResponse.class, "test-access-token")).thenReturn(null);
        String credentialEndpoint = issuerWellKnownResponse.getCredentialEndPoint();
        expectedExceptionMsg = "resource_not_found --> VC Credential Issue API not accessible";


        RuntimeException actualException = assertThrows(RuntimeException.class, () -> {
            credentialUtilService.downloadCredential(credentialEndpoint, vcCredentialRequest, "test-access-token");
        });

        assertEquals(expectedExceptionMsg, actualException.getMessage());
    }

    @Test
    public void shouldReturnVCCredentialWhenCallingCredentialEndpointWithCredentialRequest() {
        CredentialsSupportedResponse credentialsSupportedResponse = getCredentialSupportedResponse("CredentialType1");
        CredentialIssuerWellKnownResponse issuerWellKnownResponse = getCredentialIssuerWellKnownResponseDto(issuerId, Map.of("CredentialType1", credentialsSupportedResponse));
        VCCredentialRequest vcCredentialRequest = getVCCredentialRequestDTO();
        VCCredentialResponse expectedCredentialResponse = getVCCredentialResponseDTO("RSASignature2020");
        Mockito.when(restApiClient.postApi(issuerWellKnownResponse.getCredentialEndPoint(), MediaType.APPLICATION_JSON, vcCredentialRequest, VCCredentialResponse.class, "test-access-token")).thenReturn(expectedCredentialResponse);

        VCCredentialResponse actualCredentialResponse = credentialUtilService.downloadCredential(issuerWellKnownResponse.getCredentialEndPoint(), vcCredentialRequest, "test-access-token");

        assertEquals(expectedCredentialResponse, actualCredentialResponse);
    }

    @Test
    public void shouldGenerateVCCredentialRequestForProvidedIssuerAndCredentialType() throws Exception {
        CredentialsSupportedResponse credentialsSupportedResponse = getCredentialSupportedResponse("CredentialType1");
        CredentialIssuerWellKnownResponse issuerWellKnownResponse = getCredentialIssuerWellKnownResponseDto(issuerId, Map.of("CredentialType1", credentialsSupportedResponse));
        VCCredentialRequest expectedVCCredentialRequest = getVCCredentialRequestDTO();
        Mockito.when(joseUtil.generateJwt(any(String.class), any(String.class), any(String.class))).thenReturn("jwt");

        VCCredentialRequest actualVCCredentialRequest = credentialUtilService.generateVCCredentialRequest(issuerDTO, issuerWellKnownResponse, credentialsSupportedResponse, "test-access-token", "walletId", "walletKey", false);

        assertEquals(expectedVCCredentialRequest, actualVCCredentialRequest);
    }

    @Test
    public void shouldThrowExceptionWhenInvalidAlgoIsProvidedForGeneratingJWTDuringCredentialRequestGeneration() throws Exception {
        CredentialsSupportedResponse credentialsSupportedResponse = getCredentialSupportedResponse("CredentialType1");
        CredentialIssuerWellKnownResponse issuerWellKnownResponse = getCredentialIssuerWellKnownResponseDto(issuerId, Map.of("CredentialType1", credentialsSupportedResponse));
        Mockito.when(joseUtil.generateJwt(any(String.class), any(String.class), any(String.class))).thenThrow(new AssertionError("Unexpected algorithm type: dfs"));

        AssertionError actualError = assertThrows(AssertionError.class, () -> {
            credentialUtilService.generateVCCredentialRequest(issuerDTO, issuerWellKnownResponse, credentialsSupportedResponse, "test-access-token", "walletId", "walletKey", false);
        });

        assertEquals("Unexpected algorithm type: dfs", actualError.getMessage());
    }

    @Test
    public void shouldReturnTrueIfAValidCredentialIsPassedForVerification() throws VCVerificationException, JsonProcessingException {
        VCCredentialResponse vc = TestUtilities.getVCCredentialResponseDTO("ed25519Signature2020");
        VerificationResult verificationResult = new VerificationResult(true, "", "");
        Mockito.when(credentialsVerifier.verify(any(String.class), eq(CredentialFormat.LDP_VC))).thenReturn(verificationResult);
        Mockito.when(objectMapper.writeValueAsString(vc.getCredential())).thenReturn("vc");

        Boolean verificationStatus = credentialUtilService.verifyCredential(vc);

        assertTrue(verificationStatus);
    }

    @Test
    public void shouldThrowExceptionIfInvalidCredentialIsPassedForVerification() throws VCVerificationException, JsonProcessingException {
        VCCredentialResponse vc = TestUtilities.getVCCredentialResponseDTO("ed25519Signature2020");
        VerificationResult verificationResult = new VerificationResult(false, "Verification failed for the provided credentials", "Verification Failed!");
        Mockito.when(credentialsVerifier.verify(any(String.class), eq(CredentialFormat.LDP_VC))).thenReturn(verificationResult);
        Mockito.when(objectMapper.writeValueAsString(vc.getCredential())).thenReturn("vc");
        expectedExceptionMsg = "verification failed! --> Verification failed for the provided credentials";

        VCVerificationException actualException = assertThrows(VCVerificationException.class, () ->
                credentialUtilService.verifyCredential(vc)
        );

        assertEquals(expectedExceptionMsg, actualException.getMessage());
    }

    @Test
    public void shouldThrowExceptionIfDownloadedResponseContainsSigningAlgoNotSupportedByMimoto() {
        CredentialsSupportedResponse credentialsSupportedResponse = getCredentialSupportedResponse("CredentialType1");
        ProofTypesSupported proofTypesSupported = new ProofTypesSupported();
        proofTypesSupported.setProofSigningAlgValuesSupported(List.of("ps256"));
        credentialsSupportedResponse.setProofTypesSupported(Map.of("jwt", proofTypesSupported));
        CredentialIssuerWellKnownResponse issuerWellKnownResponse = getCredentialIssuerWellKnownResponseDto(issuerId, Map.of("CredentialType1", credentialsSupportedResponse));

        IllegalArgumentException actualError = assertThrows(IllegalArgumentException.class, () -> {
            credentialUtilService.generateVCCredentialRequest(issuerDTO, issuerWellKnownResponse, credentialsSupportedResponse, "test-access-token", "walletId", "walletKey", true);
        });

        assertEquals("Unsupported signing algorithm: ps256", actualError.getMessage());
    }

    @Test
    public void shouldSuccessfullyGeneratePdfForVerifiableCredential() throws Exception {
        VCCredentialResponse vcCredentialResponse = getVCCredentialResponseDTO("CredentialType1");
        issuerDTO.setQr_code_type(QRCodeType.None);
        Mockito.when(utilities.getCredentialSupportedTemplateString(issuerDTO.getIssuer_id(), "CredentialType1")).thenReturn("<html><body><h1>PDF</h1></body></html>");
        ByteArrayInputStream expectedPDFByteArray = generatePdfFromHTML();

        ByteArrayInputStream actualPDFByteArray =
                credentialUtilService.generatePdfForVerifiableCredentials("CredentialType1", vcCredentialResponse, issuerDTO, issuerConfig.getCredentialConfigurationsSupported().get("CredentialType1"), "https://datashare_url", "once", "en");

        String expectedText = extractTextFromPdf(expectedPDFByteArray);
        String actualText = extractTextFromPdf(actualPDFByteArray);

        assertEquals(expectedText, actualText);
    }
}
