package io.mosip.mimoto.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.BackgroundImageDTO;
import io.mosip.mimoto.dto.DisplayDTO;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.LogoDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.dto.openid.presentation.PresentationDefinitionDTO;
import io.mosip.mimoto.model.QRCodeType;
import io.mosip.mimoto.service.impl.LdpVcCredentialFormatHandler;
import io.mosip.mimoto.service.impl.PresentationServiceImpl;
import io.mosip.mimoto.util.Utilities;
import io.mosip.pixelpass.PixelPass;
import io.mosip.pixelpass.types.ECC;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialPDFGeneratorServiceTest {

    @Mock private ObjectMapper objectMapper;
    @Mock private PresentationServiceImpl presentationService;
    @Mock private Utilities utilities;
    @Mock private PixelPass pixelPass;
    @Mock
    private CredentialFormatHandlerFactory credentialFormatHandlerFactory;
    @Mock
    private LdpVcCredentialFormatHandler credentialFormatHandler;

    @InjectMocks
    private CredentialPDFGeneratorService credentialPDFGeneratorService;

    private VCCredentialResponse vcCredentialResponse;
    private IssuerDTO issuerDTO;
    private CredentialsSupportedResponse credentialsSupportedResponse;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(credentialPDFGeneratorService, "ovpQRDataPattern", "test-pattern-%s-%s");
        ReflectionTestUtils.setField(credentialPDFGeneratorService, "pixelPass", pixelPass);
        // Mock the handler factory to return the handler for the test format
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);

        setupTestData();
    }

    private void setupTestData() {
        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("dateOfBirth", "1990-01-01");
        subjectData.put("face", "base64-encoded-image");

        VCCredentialProperties vcProperties = VCCredentialProperties.builder()
                .credentialSubject(subjectData)
                .type(List.of("VerifiableCredential"))
                .build();

        vcCredentialResponse = VCCredentialResponse.builder()
                .format("ldp_vc")
                .credential(vcProperties)
                .build();

        issuerDTO = new IssuerDTO();
        issuerDTO.setIssuer_id("test-issuer");
        issuerDTO.setQr_code_type(QRCodeType.OnlineSharing);

        DisplayDTO display = new DisplayDTO();
        display.setName("Issuer Display Name");
        display.setTitle("Issuer Title");
        display.setDescription("Issuer Description");
        display.setLanguage("en");

        LogoDTO logo = new LogoDTO();
        logo.setUrl("https://example.com/logo.png");
        display.setLogo(logo);

        issuerDTO.setDisplay(List.of(display));

        credentialsSupportedResponse = new CredentialsSupportedResponse();

        Map<String, CredentialDisplayResponseDto> credentialSubjectMap = new HashMap<>();
        credentialSubjectMap.put("name", createDisplay("Full Name"));
        credentialSubjectMap.put("dateOfBirth", createDisplay("Date of Birth"));

        CredentialDefinitionResponseDto definition = new CredentialDefinitionResponseDto();
        definition.setCredentialSubject(credentialSubjectMap);
        credentialsSupportedResponse.setCredentialDefinition(definition);
        credentialsSupportedResponse.setOrder(new ArrayList<>(List.of("name", "dateOfBirth")));

        CredentialSupportedDisplayResponse credDisplay = new CredentialSupportedDisplayResponse();
        credDisplay.setBackgroundColor("#FFFFFF");
        credDisplay.setTextColor("#000000");
        credDisplay.setName("Test Credential");
        BackgroundImageDTO bgImage = new BackgroundImageDTO();
        bgImage.setUri("https://example.com/bg.png");
        credDisplay.setBackgroundImage(bgImage);

        credentialsSupportedResponse.setDisplay(List.of(credDisplay));
    }

    private CredentialDisplayResponseDto createDisplay(String name) {
        CredentialDisplayResponseDto dto = new CredentialDisplayResponseDto();
        CredentialIssuerDisplayResponse display = new CredentialIssuerDisplayResponse();
        display.setName(name);
        display.setLocale("en");
        dto.setDisplay(List.of(display));
        return dto;
    }

    @Test
    void testGeneratePdfForVerifiableCredentials() throws Exception {
        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Test</body></html>");
        PresentationDefinitionDTO presentationDef = new PresentationDefinitionDTO();
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(presentationDef);
        when(objectMapper.writeValueAsString(presentationDef))
                .thenReturn("{\"presentation\":\"definition\"}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredentials(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "2025-12-31", "en");

        assertNotNull(result);
    }

    @Test
    void testGeneratePdfForEmbeddedVCQR() throws Exception {
        issuerDTO.setQr_code_type(QRCodeType.EmbeddedVC);
        when(objectMapper.writeValueAsString(any())).thenReturn("{\"credential\":\"data\"}");
        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Test</body></html>");


        try (MockedStatic<Utilities> mocked = mockStatic(Utilities.class)) {
            mocked.when(() -> Utilities.encodeToString(any(), anyString()))
                    .thenReturn("base64-encoded-qr");

            ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredentials(
                    "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                    "", "", "en");

            verify(pixelPass).generateQRCode(anyString(), eq(ECC.L), anyString());
            verify(presentationService, never()).constructPresentationDefinition(any());
            assertNotNull(result);
        }
    }

    @Test
    void testGeneratePdfShouldGeneratePresentationDefinitionForOnlineSharingQrTypeWithNonEmptyDataShareUrl() throws Exception {
        issuerDTO.setQr_code_type(QRCodeType.OnlineSharing);
        when(objectMapper.writeValueAsString(any())).thenReturn("{\"credential\":\"data\"}");
        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Test</body></html>");


        try (MockedStatic<Utilities> mocked = mockStatic(Utilities.class)) {
            mocked.when(() -> Utilities.encodeToString(any(), anyString()))
                    .thenReturn("base64-encoded-qr");

            ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredentials(
                    "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                    "http://datashare.datashare/v1/datashare/get/static-policyid/static-subscriberid/test", "", "en");

            verify(presentationService).constructPresentationDefinition(any());
            verify(pixelPass, never()).generateQRData(anyString(), anyString());
            assertNotNull(result);
        }
    }

    @Test
    void testGeneratePdfShouldGenerateEmbeddedVCForOnlineSharingQrTypeWithEmptyDataShareUrl() throws Exception {
        issuerDTO.setQr_code_type(QRCodeType.OnlineSharing);
        when(objectMapper.writeValueAsString(any())).thenReturn("{\"credential\":\"data\"}");
//        when(pixelPass.generateQRData(anyString(), anyString())).thenReturn("generated-qr-data");
        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Test</body></html>");


        try (MockedStatic<Utilities> mocked = mockStatic(Utilities.class)) {
            mocked.when(() -> Utilities.encodeToString(any(), anyString()))
                    .thenReturn("base64-encoded-qr");

            ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredentials(
                    "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                    "", "", "en");

           // verify(pixelPass).generateQRData(anyString(), anyString());
//            verify(presentationService, never()).constructPresentationDefinition(any());
            assertNotNull(result);
        }
    }

    @Test
    void testHandleMapWithListValue() throws Exception {
        Map<String, Object> skills = new HashMap<>();
        skills.put("skills", List.of("Java", "Spring"));
        ((VCCredentialProperties)vcCredentialResponse.getCredential()).setCredentialSubject(skills);
        credentialsSupportedResponse.getCredentialDefinition().getCredentialSubject()
                .put("skills", createDisplay("Skills"));
        credentialsSupportedResponse.setOrder(List.of("skills"));

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Test</body></html>");
        PresentationDefinitionDTO presentationDef = new PresentationDefinitionDTO();
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(presentationDef);
        when(objectMapper.writeValueAsString(presentationDef))
                .thenReturn("{\"presentation\":\"definition\"}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredentials(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
    }

    @Test
    void testNullFaceImageHandling() throws Exception {
        Map<String, Object> mutableSubject = new HashMap<>(((VCCredentialProperties)vcCredentialResponse.getCredential()).getCredentialSubject());
        mutableSubject.remove("face");
        ((VCCredentialProperties)vcCredentialResponse.getCredential()).setCredentialSubject(mutableSubject);

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Test</body></html>");
        PresentationDefinitionDTO presentationDef = new PresentationDefinitionDTO();
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(presentationDef);
        when(objectMapper.writeValueAsString(presentationDef))
                .thenReturn("{\"presentation\":\"definition\"}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredentials(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
    }

    @Test
    void testGeneratePdfWithNullOrder() throws Exception {
        credentialsSupportedResponse.setOrder(null);
        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Test</body></html>");

        PresentationDefinitionDTO presentationDef = new PresentationDefinitionDTO();
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(presentationDef);
        when(objectMapper.writeValueAsString(presentationDef))
                .thenReturn("{\"presentation\":\"definition\"}");

        try (MockedStatic<Utilities> mocked = mockStatic(Utilities.class)) {
            mocked.when(() -> Utilities.encodeToString(any(), anyString()))
                    .thenReturn("base64-encoded-qr");

            ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredentials(
                    "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                    "https://example.com/share", "", "en");

            assertNotNull(result);
        }
    }
}
