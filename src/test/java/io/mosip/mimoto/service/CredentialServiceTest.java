package io.mosip.mimoto.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.model.QRCodeType;
import io.mosip.mimoto.service.impl.CredentialServiceImpl;
import io.mosip.mimoto.service.impl.IdpServiceImpl;
import io.mosip.mimoto.service.impl.IssuersServiceImpl;
import io.mosip.mimoto.util.JoseUtil;
import io.mosip.mimoto.util.RestApiClient;
import io.mosip.mimoto.util.TestUtilities;
import io.mosip.mimoto.util.Utilities;
import io.mosip.vercred.vcverifier.CredentialsVerifier;
import io.mosip.vercred.vcverifier.constants.CredentialFormat;
import io.mosip.vercred.vcverifier.data.VerificationResult;
import lombok.extern.slf4j.Slf4j;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpEntity;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static io.mosip.mimoto.util.TestUtilities.*;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.doReturn;

@RunWith(MockitoJUnitRunner.class)
@SpringBootTest
@Slf4j
public class CredentialServiceTest {

    @Mock
    CredentialsVerifier credentialsVerifier;
    @Mock
    ObjectMapper objectMapper;
    @Spy
    @InjectMocks
    CredentialServiceImpl credentialService = new CredentialServiceImpl();

    @Mock
    IssuersServiceImpl issuersService;

    @Mock
    RestTemplate restTemplate;

    @Mock
    IdpServiceImpl idpService;

    @Mock
    RestApiClient restApiClient;

    @Mock
    JoseUtil joseUtil;

    @Mock
    Utilities utilities;

    private Map<String, String> tokenRequestParams = Map.of(
            "grant_type", "client_credentials",
            "client_id", "test-client"
    );

    TokenResponseDTO expectedTokenResponse;
    String tokenEndpoint, issuerId, expectedExceptionMsg;
    IssuerDTO issuerDTO;
    HttpEntity<MultiValueMap<String, String>> mockRequest;
    CredentialIssuerConfiguration issuerConfig;

    @Before
    public void setUp() throws Exception {
        issuerId = "Issuer1";
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

        Mockito.when(idpService.constructGetTokenRequest(tokenRequestParams, issuerDTO, tokenEndpoint))
                .thenReturn(mockRequest);
        Mockito.when(idpService.getTokenEndpoint(issuerConfig))
                .thenReturn(tokenEndpoint);
        Mockito.when(restTemplate.postForObject(tokenEndpoint, mockRequest, TokenResponseDTO.class))
                .thenReturn(expectedTokenResponse);
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
    public void shouldReturnTrueIfAValidCredentialIsPassedForVerification() throws VCVerificationException, JsonProcessingException {
        VCCredentialResponse vc = TestUtilities.getVCCredentialResponseDTO("ed25519Signature2020");
        VerificationResult verificationResult = new VerificationResult(true, "", "");
        Mockito.when(credentialsVerifier.verify(any(String.class), eq(CredentialFormat.LDP_VC))).thenReturn(verificationResult);
        Mockito.when(objectMapper.writeValueAsString(vc.getCredential())).thenReturn("vc");
        Boolean verificationStatus = credentialService.verifyCredential(vc);

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
                credentialService.verifyCredential(vc)
        );

        assertEquals(expectedExceptionMsg, actualException.getMessage());
    }

    @Test
    public void shouldReturnTokenResponseForValidTokenEndpoint() throws Exception {

        TokenResponseDTO actualTokenResponse = credentialService.getTokenResponse(tokenRequestParams, "Issuer1");

        assertEquals(expectedTokenResponse, actualTokenResponse);
    }

    @Test
    public void shouldThrowExceptionIfResponseIsNullWhenFetchingTokenResponse() throws Exception {
        Mockito.when(restTemplate.postForObject(tokenEndpoint, mockRequest, TokenResponseDTO.class))
                .thenReturn(null);

        IdpException actualException = assertThrows(IdpException.class, () -> {
            credentialService.getTokenResponse(tokenRequestParams, "Issuer1");
        });

        assertEquals("RESIDENT-APP-034 --> Exception occurred while performing the authorization", actualException.getMessage());
    }

    @Test
    public void shouldThrowExceptionOnFetchingCredentialFromCredentialEndpointFailure() {
        CredentialsSupportedResponse credentialsSupportedResponse = getCredentialSupportedResponse("CredentialType1");
        CredentialIssuerWellKnownResponse issuerWellKnownResponse = getCredentialIssuerWellKnownResponseDto(issuerId, Map.of("CredentialType1", credentialsSupportedResponse));
        VCCredentialRequest vcCredentialRequest = getVCCredentialRequestDTO();
        Mockito.when(restApiClient.postApi(issuerWellKnownResponse.getCredentialEndPoint(), MediaType.APPLICATION_JSON, vcCredentialRequest, VCCredentialResponse.class, "test-access-token")).thenReturn(null);
        String credentialEndpoint = issuerWellKnownResponse.getCredentialEndPoint();
        expectedExceptionMsg = "VC Credential Issue API not accessible";


        RuntimeException actualException = assertThrows(RuntimeException.class, () -> {
            credentialService.downloadCredential(credentialEndpoint, vcCredentialRequest, "test-access-token");
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

        VCCredentialResponse actualCredentialResponse = credentialService.downloadCredential(issuerWellKnownResponse.getCredentialEndPoint(), vcCredentialRequest, "test-access-token");

        assertEquals(expectedCredentialResponse, actualCredentialResponse);
    }

    @Test
    public void shouldGenerateVCCredentialRequestForProvidedIssuerAndCredentialType() throws Exception {
        CredentialsSupportedResponse credentialsSupportedResponse = getCredentialSupportedResponse("CredentialType1");
        CredentialIssuerWellKnownResponse issuerWellKnownResponse = getCredentialIssuerWellKnownResponseDto(issuerId, Map.of("CredentialType1", credentialsSupportedResponse));
        VCCredentialRequest expectedVCCredentialRequest = getVCCredentialRequestDTO();
        Mockito.when(joseUtil.generateJwt(any(String.class), any(String.class), any(String.class))).thenReturn("jwt");

        VCCredentialRequest actualVCCredentialRequest = credentialService.generateVCCredentialRequest(issuerDTO, issuerWellKnownResponse, credentialsSupportedResponse, "test-access-token");

        assertEquals(expectedVCCredentialRequest, actualVCCredentialRequest);
    }

    @Test
    public void shouldThrowExceptionWhenInvalidAlgoIsProvidedForGeneratingJWTDuringCredentialRequestGeneration() throws Exception {
        CredentialsSupportedResponse credentialsSupportedResponse = getCredentialSupportedResponse("CredentialType1");
        CredentialIssuerWellKnownResponse issuerWellKnownResponse = getCredentialIssuerWellKnownResponseDto(issuerId, Map.of("CredentialType1", credentialsSupportedResponse));
        Mockito.when(joseUtil.generateJwt(any(String.class), any(String.class), any(String.class))).thenThrow(new AssertionError("Unexpected algorithm type: dfs"));

        AssertionError actualError = assertThrows(AssertionError.class, () -> {
            credentialService.generateVCCredentialRequest(issuerDTO, issuerWellKnownResponse, credentialsSupportedResponse, "test-access-token");
        });

        assertEquals("Unexpected algorithm type: dfs", actualError.getMessage());
    }

    @Test
    public void shouldThrowExceptionIfDownloadedVCSignatureVerificationFailed() throws Exception {
        Mockito.when(issuersService.getIssuerDetails(issuerId)).thenReturn(issuerDTO);
        Mockito.when(issuersService.getIssuerConfiguration(issuerId)).thenReturn(issuerConfig);
        doReturn(getVCCredentialRequestDTO()).when(credentialService).generateVCCredentialRequest(
                any(IssuerDTO.class),
                any(CredentialIssuerWellKnownResponse.class),
                any(CredentialsSupportedResponse.class),
                any(String.class)
        );
        VCCredentialResponse vcCredentialResponse = getVCCredentialResponseDTO("CredentialType1");
        doReturn(vcCredentialResponse).when(credentialService).downloadCredential(any(String.class),
                any(VCCredentialRequest.class),
                any(String.class));
        doReturn(false).when(credentialService).verifyCredential(vcCredentialResponse);

        VCVerificationException actualException = assertThrows(VCVerificationException.class, () ->
                credentialService.downloadCredentialAsPDF(issuerId, "CredentialType1", expectedTokenResponse, "once", "en"));

        assertEquals("signature_verification_failed --> Error while doing signature verification", actualException.getMessage());
    }

    @Test
    public void shouldReturnDownloadedVCAsPDFIfSignatureVerificationIsSuccessful() throws Exception {
        Mockito.when(issuersService.getIssuerDetails(issuerId)).thenReturn(issuerDTO);
        Mockito.when(issuersService.getIssuerConfiguration(issuerId)).thenReturn(issuerConfig);
        doReturn(getVCCredentialRequestDTO()).when(credentialService).generateVCCredentialRequest(
                any(IssuerDTO.class),
                any(CredentialIssuerWellKnownResponse.class),
                any(CredentialsSupportedResponse.class),
                any(String.class)
        );
        VCCredentialResponse vcCredentialResponse = getVCCredentialResponseDTO("CredentialType1");
        doReturn(vcCredentialResponse).when(credentialService).downloadCredential(any(String.class),
                any(VCCredentialRequest.class),
                any(String.class));
        doReturn(true).when(credentialService).verifyCredential(vcCredentialResponse);
        issuerDTO.setQr_code_type(QRCodeType.None);
        Mockito.when(utilities.getCredentialSupportedTemplateString(issuerDTO.getIssuer_id(), "CredentialType1")).thenReturn("<html><body><h1>PDF</h1></body></html>");
        ByteArrayInputStream expectedPDFByteArray = generatePdfFromHTML();

        ByteArrayInputStream actualPDFByteArray =
                credentialService.downloadCredentialAsPDF(issuerId, "CredentialType1", expectedTokenResponse, "once", "en");

        String expectedText = extractTextFromPdf(expectedPDFByteArray);
        String actualText = extractTextFromPdf(actualPDFByteArray);

        assertEquals(expectedText, actualText);
    }
}
