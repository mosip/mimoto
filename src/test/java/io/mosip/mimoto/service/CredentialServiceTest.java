package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.exception.VCVerificationException;
import io.mosip.mimoto.model.QRCodeType;
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

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
        VCCredentialResponse vcCredentialResponse = getVCCredentialResponseDTO("CredentialType1");
        when(restApiClient.postApi(
                any(String.class),
                any(MediaType.class),
                any(VCCredentialRequest.class),
                eq(VCCredentialResponse.class),
                any(String.class)
        )).thenReturn(vcCredentialResponse);
        when(credentialVerifierService.verify(vcCredentialResponse)).thenReturn(false);
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
        VCCredentialResponse vcCredentialResponse = getVCCredentialResponseDTO("CredentialType1");
        when(restApiClient.postApi(
                any(String.class),
                any(MediaType.class),
                any(VCCredentialRequest.class),
                eq(VCCredentialResponse.class),
                any(String.class)
        )).thenReturn(vcCredentialResponse);
        when(credentialVerifierService.verify(vcCredentialResponse)).thenReturn(true);
        issuerDTO.setQr_code_type(QRCodeType.None);

        ByteArrayInputStream expectedPDFByteArray = generatePdfFromHTML();
        Mockito.when(credentialUtilService.generatePdfForVerifiableCredentials("CredentialType1", vcCredentialResponse, issuerDTO, issuerConfig.getCredentialConfigurationsSupported().get("CredentialType1"), "", "once", "en")).thenReturn(expectedPDFByteArray);

        ByteArrayInputStream actualPDFByteArray =
                credentialService.downloadCredentialAsPDF(issuerId, "CredentialType1", expectedTokenResponse, "once", "en");

        assertEquals(expectedPDFByteArray, actualPDFByteArray);
    }
}
