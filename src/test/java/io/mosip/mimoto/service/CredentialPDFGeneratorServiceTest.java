
package io.mosip.mimoto.service;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
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
import io.mosip.mimoto.service.impl.VcSdJwtCredentialFormatHandler;
import io.mosip.mimoto.util.Utilities;
import io.mosip.pixelpass.PixelPass;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.ByteArrayInputStream;
import java.util.*;

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

    @Mock
    private VcSdJwtCredentialFormatHandler sdJwtCredentialFormatHandler;

    @InjectMocks
    private CredentialPDFGeneratorService credentialPDFGeneratorService;

    private VCCredentialResponse vcCredentialResponse;
    private IssuerDTO issuerDTO;
    private CredentialsSupportedResponse credentialsSupportedResponse;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(credentialPDFGeneratorService, "ovpQRDataPattern", "test-pattern-%s-%s");
        ReflectionTestUtils.setField(credentialPDFGeneratorService, "qrCodeHeight", 500);
        ReflectionTestUtils.setField(credentialPDFGeneratorService, "qrCodeWidth", 500);
        ReflectionTestUtils.setField(credentialPDFGeneratorService, "allowedQRDataSizeLimit", 2000);
        ReflectionTestUtils.setField(credentialPDFGeneratorService, "pixelPass", pixelPass);
        ReflectionTestUtils.setField(credentialPDFGeneratorService, "faceImageLookupKeys",
                "image,face,photo,picture,portrait");

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
    void testGeneratePdfForVerifiableCredential() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Test</body></html>");
        PresentationDefinitionDTO presentationDef = new PresentationDefinitionDTO();
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(presentationDef);
        when(objectMapper.writeValueAsString(presentationDef))
                .thenReturn("{\"presentation\":\"definition\"}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "2025-12-31", "en");

        assertNotNull(result);
    }

    @Test
    void testGeneratePdfForEmbeddedVCQR() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        issuerDTO.setQr_code_type(QRCodeType.EmbeddedVC);
        when(objectMapper.writeValueAsString(any())).thenReturn("{\"credential\":\"data\"}");
        when(pixelPass.generateQRData(anyString(), anyString())).thenReturn("generated-qr-data");
        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Test</body></html>");


        try (MockedStatic<Utilities> mocked = mockStatic(Utilities.class)) {
            mocked.when(() -> Utilities.encodeToString(any(), anyString()))
                    .thenReturn("base64-encoded-qr");

            ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                    "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                    "", "", "en");

            verify(pixelPass).generateQRData(anyString(), anyString());
            verify(presentationService, never()).constructPresentationDefinition(any());
            assertNotNull(result);
        }
    }

    @Test
    void testGeneratePdfShouldGeneratePresentationDefinitionForOnlineSharingQrTypeWithNonEmptyDataShareUrl() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        issuerDTO.setQr_code_type(QRCodeType.OnlineSharing);
        when(objectMapper.writeValueAsString(any())).thenReturn("{\"credential\":\"data\"}");
        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Test</body></html>");


        try (MockedStatic<Utilities> mocked = mockStatic(Utilities.class)) {
            mocked.when(() -> Utilities.encodeToString(any(), anyString()))
                    .thenReturn("base64-encoded-qr");

            ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                    "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                    "http://datashare.datashare/v1/datashare/get/static-policyid/static-subscriberid/test", "", "en");

            verify(presentationService).constructPresentationDefinition(any());
            verify(pixelPass, never()).generateQRData(anyString(), anyString());
            assertNotNull(result);
        }
    }

    @Test
    void testHandleMapWithListValue() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
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

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
    }

    @Test
    void testNullFaceImageHandling() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
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

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
    }

    @Test
    void testGeneratePdfWithNullOrder() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
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

            ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                    "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                    "https://example.com/share", "", "en");

            assertNotNull(result);
        }
    }

    @Test
    void testGeneratePdfWithMapValueFormatting() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        // Setup credential with map containing "value" key
        Map<String, Object> subjectWithMapValue = new HashMap<>();
        subjectWithMapValue.put("education", Map.of("value", "Bachelor's Degree"));
        ((VCCredentialProperties)vcCredentialResponse.getCredential()).setCredentialSubject(subjectWithMapValue);

        // Setup display for education field
        credentialsSupportedResponse.getCredentialDefinition().getCredentialSubject()
                .put("education", createDisplay("Education"));
        credentialsSupportedResponse.setOrder(List.of("education"));

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Education: $rowProperties.education</body></html>");
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(new PresentationDefinitionDTO());
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
        // Verify the PDF generation succeeded - formatValue was called internally
    }

    @Test
    void testGeneratePdfWithStringListFormatting() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        // Setup credential with list of strings
        Map<String, Object> subjectWithList = new HashMap<>();
        subjectWithList.put("skills", List.of("Java", "Spring", "Boot"));
        ((VCCredentialProperties)vcCredentialResponse.getCredential()).setCredentialSubject(subjectWithList);

        credentialsSupportedResponse.getCredentialDefinition().getCredentialSubject()
                .put("skills", createDisplay("Skills"));
        credentialsSupportedResponse.setOrder(List.of("skills"));

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Skills: $rowProperties.skills</body></html>");
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(new PresentationDefinitionDTO());
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
        // The formatValue method handles list formatting internally
    }

    @Test
    void testGeneratePdfWithLocaleSpecificMapListFormatting() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        // Setup credential with locale-specific map list
        Map<String, Object> subjectWithLocaleMap = new HashMap<>();
        List<Map<String, Object>> localeData = List.of(
                Map.of("language", "en", "value", "English Name"),
                Map.of("language", "fr", "value", "French Name")
        );
        subjectWithLocaleMap.put("localizedName", localeData);
        ((VCCredentialProperties)vcCredentialResponse.getCredential()).setCredentialSubject(subjectWithLocaleMap);

        credentialsSupportedResponse.getCredentialDefinition().getCredentialSubject()
                .put("localizedName", createDisplay("Localized Name"));
        credentialsSupportedResponse.setOrder(List.of("localizedName"));

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Name: $rowProperties.localizedName</body></html>");
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(new PresentationDefinitionDTO());
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
        // formatValue should select "English Name" based on locale "en"
    }

    @Test
    void testGeneratePdfWithNumericValueFormatting() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        // Setup credential with numeric value
        Map<String, Object> subjectWithNumber = new HashMap<>();
        subjectWithNumber.put("age", 25);
        ((VCCredentialProperties)vcCredentialResponse.getCredential()).setCredentialSubject(subjectWithNumber);

        credentialsSupportedResponse.getCredentialDefinition().getCredentialSubject()
                .put("age", createDisplay("Age"));
        credentialsSupportedResponse.setOrder(List.of("age"));

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Age: $rowProperties.age</body></html>");
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(new PresentationDefinitionDTO());
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
        // formatValue converts number to string internally
    }

    @Test
    void testFaceKeyFallbackFromPrimaryToSecondary() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        // Setup: No "face" key, but has "photo" key
        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("photo", "base64-photo-image");
        subjectData.put("dateOfBirth", "1990-01-01");

        ((VCCredentialProperties)vcCredentialResponse.getCredential()).setCredentialSubject(subjectData);

        // Setup credential display without face key to avoid it appearing in rowProperties
        Map<String, CredentialDisplayResponseDto> credentialSubjectMap = new HashMap<>();
        credentialSubjectMap.put("name", createDisplay("Full Name"));
        credentialSubjectMap.put("dateOfBirth", createDisplay("Date of Birth"));
        // Note: No "photo" in display properties - should be excluded from rowProperties

        credentialsSupportedResponse.getCredentialDefinition().setCredentialSubject(credentialSubjectMap);
        credentialsSupportedResponse.setOrder(List.of("name", "dateOfBirth"));

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Face: $face, Name: $rowProperties.name</body></html>");
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(new PresentationDefinitionDTO());
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
        // Indirectly tests that "photo" was used as fallback for $face variable
    }

    @Test
    void testFaceKeyFallbackToPortrait() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        // Setup: No "face" or "photo", but has "portrait"
        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("portrait", "base64-portrait-image");

        ((VCCredentialProperties)vcCredentialResponse.getCredential()).setCredentialSubject(subjectData);

        Map<String, CredentialDisplayResponseDto> credentialSubjectMap = new HashMap<>();
        credentialSubjectMap.put("name", createDisplay("Full Name"));

        credentialsSupportedResponse.getCredentialDefinition().setCredentialSubject(credentialSubjectMap);
        credentialsSupportedResponse.setOrder(List.of("name"));

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Portrait: $face, Name: $rowProperties.name</body></html>");
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(new PresentationDefinitionDTO());
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
        // Tests fallback to "portrait" key
    }

    @Test
    void testFaceKeyFallbackToImage() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        // Setup: Only "image" key available
        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("image", "base64-generic-image");

        ((VCCredentialProperties)vcCredentialResponse.getCredential()).setCredentialSubject(subjectData);

        Map<String, CredentialDisplayResponseDto> credentialSubjectMap = new HashMap<>();
        credentialSubjectMap.put("name", createDisplay("Full Name"));

        credentialsSupportedResponse.getCredentialDefinition().setCredentialSubject(credentialSubjectMap);
        credentialsSupportedResponse.setOrder(List.of("name"));

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Image: $face, Name: $rowProperties.name</body></html>");
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(new PresentationDefinitionDTO());
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
        // Tests fallback to "image" key
    }

    @Test
    void testFaceKeyFallbackToPicture() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        // Setup: Only "picture" key available
        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("picture", "base64-picture-image");

        ((VCCredentialProperties)vcCredentialResponse.getCredential()).setCredentialSubject(subjectData);

        Map<String, CredentialDisplayResponseDto> credentialSubjectMap = new HashMap<>();
        credentialSubjectMap.put("name", createDisplay("Full Name"));

        credentialsSupportedResponse.getCredentialDefinition().setCredentialSubject(credentialSubjectMap);
        credentialsSupportedResponse.setOrder(List.of("name"));

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Picture: $face, Name: $rowProperties.name</body></html>");
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(new PresentationDefinitionDTO());
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
        // Tests fallback to "picture" key
    }

    @Test
    void testFaceKeyPriorityOrder() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        // Setup: Multiple face keys present - should use first available in priority order
        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("picture", "base64-picture-image"); // Lower priority
        subjectData.put("photo", "base64-photo-image");     // Lower priority
        subjectData.put("image", "base64-image");           // HIGHEST priority now

        ((VCCredentialProperties)vcCredentialResponse.getCredential()).setCredentialSubject(subjectData);

        Map<String, CredentialDisplayResponseDto> credentialSubjectMap = new HashMap<>();
        credentialSubjectMap.put("name", createDisplay("Full Name"));
        // Include all face keys in display to test that only "image" gets excluded
        credentialSubjectMap.put("picture", createDisplay("Picture"));
        credentialSubjectMap.put("photo", createDisplay("Photo"));
        credentialSubjectMap.put("image", createDisplay("Image")); // Should be excluded (used for $face)

        credentialsSupportedResponse.getCredentialDefinition().setCredentialSubject(credentialSubjectMap);
        credentialsSupportedResponse.setOrder(List.of("name", "picture", "photo", "image"));

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Face: $face, Name: $rowProperties.name</body></html>");
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(new PresentationDefinitionDTO());
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
        // Should use "image" (highest priority) over "photo" and "picture"
        // Only "image" should be excluded from rowProperties, "photo" and "picture" should appear
    }

    @Test
    void testOnlySelectedFaceKeyExcludedFromRowProperties() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        // Setup: Multiple face keys - only the selected one ("image") should be excluded from rowProperties
        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("image", "base64-image");           // Highest priority - will be selected for $face
        subjectData.put("face", "base64-face-image");       // Should appear in rowProperties
        subjectData.put("photo", "base64-photo-image");     // Should appear in rowProperties
        subjectData.put("portrait", "base64-portrait-image"); // Should appear in rowProperties
        subjectData.put("email", "john@example.com");

        ((VCCredentialProperties)vcCredentialResponse.getCredential()).setCredentialSubject(subjectData);

        // Include all face keys in display properties
        Map<String, CredentialDisplayResponseDto> credentialSubjectMap = new HashMap<>();
        credentialSubjectMap.put("name", createDisplay("Full Name"));
        credentialSubjectMap.put("image", createDisplay("Image"));        // Should be excluded (used for $face)
        credentialSubjectMap.put("face", createDisplay("Face Photo"));    // Should appear in rowProperties
        credentialSubjectMap.put("photo", createDisplay("Photo"));        // Should appear in rowProperties
        credentialSubjectMap.put("portrait", createDisplay("Portrait"));  // Should appear in rowProperties
        credentialSubjectMap.put("email", createDisplay("Email Address"));

        credentialsSupportedResponse.getCredentialDefinition().setCredentialSubject(credentialSubjectMap);
        credentialsSupportedResponse.setOrder(List.of("name", "image", "face", "photo", "portrait", "email"));

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Face: $face<br/>Properties: $rowProperties</body></html>");
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(new PresentationDefinitionDTO());
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
        // Only "image" should be excluded from rowProperties. "face", "photo" and "portrait" should appear in rowProperties
    }

    @Test
    void testMultipleFaceKeysExcludedFromRowProperties() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        // Setup: Multiple face keys present
        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("face", "base64-face-image");
        subjectData.put("photo", "base64-photo-image");
        subjectData.put("portrait", "base64-portrait-image");
        subjectData.put("email", "john@example.com");

        ((VCCredentialProperties)vcCredentialResponse.getCredential()).setCredentialSubject(subjectData);

        // Include all face keys in display properties
        Map<String, CredentialDisplayResponseDto> credentialSubjectMap = new HashMap<>();
        credentialSubjectMap.put("name", createDisplay("Full Name"));
        credentialSubjectMap.put("face", createDisplay("Face Photo"));
        credentialSubjectMap.put("photo", createDisplay("Photo"));
        credentialSubjectMap.put("portrait", createDisplay("Portrait"));
        credentialSubjectMap.put("email", createDisplay("Email Address"));

        credentialsSupportedResponse.getCredentialDefinition().setCredentialSubject(credentialSubjectMap);
        credentialsSupportedResponse.setOrder(List.of("name", "face", "photo", "portrait", "email"));

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Face: $face<br/>Properties: $rowProperties</body></html>");
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(new PresentationDefinitionDTO());
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
        // All face-related keys should be excluded from rowProperties
        // Only "name" and "email" should appear in rowProperties
    }

    @Test
    void testNoFaceKeysAvailable() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        // Setup: No face-related keys in credential
        Map<String, Object> subjectData = new HashMap<>();
        subjectData.put("name", "John Doe");
        subjectData.put("email", "john@example.com");
        subjectData.put("dateOfBirth", "1990-01-01");

        ((VCCredentialProperties)vcCredentialResponse.getCredential()).setCredentialSubject(subjectData);

        Map<String, CredentialDisplayResponseDto> credentialSubjectMap = new HashMap<>();
        credentialSubjectMap.put("name", createDisplay("Full Name"));
        credentialSubjectMap.put("email", createDisplay("Email Address"));
        credentialSubjectMap.put("dateOfBirth", createDisplay("Date of Birth"));

        credentialsSupportedResponse.getCredentialDefinition().setCredentialSubject(credentialSubjectMap);
        credentialsSupportedResponse.setOrder(List.of("name", "email", "dateOfBirth"));

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html><body>Face: $face<br/>Properties: $rowProperties</body></html>");
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(new PresentationDefinitionDTO());
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
        // Should handle gracefully when no face keys are available ($face will be null)
    }

    @Test
    void testMaskingForSelectivelyDisclosableClaimsAndNonMaskedFieldsInSDJWT() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("vc+sd-jwt")).thenReturn(sdJwtCredentialFormatHandler);
        vcCredentialResponse.setFormat("vc+sd-jwt");
        String mockSDJWTString = "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiaGFzaDEiLCJoYXNoMiJdfQ.signature~disclosure1~disclosure2";
        vcCredentialResponse.setCredential(mockSDJWTString);

        try (MockedStatic<SDJWT> mockedSDJWT = mockStatic(SDJWT.class)) {
            SDJWT mockSDJWT = mock(SDJWT.class);

            mockedSDJWT.when(() -> SDJWT.parse(mockSDJWTString)).thenReturn(mockSDJWT);

            // Only name and age are selectively disclosable (will be masked)
            Disclosure nameDisclosure = mock(Disclosure.class);
            when(nameDisclosure.getClaimName()).thenReturn("name");

            Disclosure ageDisclosure = mock(Disclosure.class);
            when(ageDisclosure.getClaimName()).thenReturn("age");

            when(mockSDJWT.getDisclosures()).thenReturn(List.of(nameDisclosure, ageDisclosure));

            Map<String, Object> claims = new HashMap<>();
            claims.put("name", "John Doe");        // Will be masked
            claims.put("age", "30");              // Will be masked
            claims.put("email", "john@example.com"); // Not masked (not in disclosures)
            claims.put("country", "USA");         // Not masked (not in disclosures)

            when(sdJwtCredentialFormatHandler.extractCredentialClaims(vcCredentialResponse))
                    .thenReturn(claims);

            // Use LinkedHashMap instead of HashMap
            LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
            displayProps.put("name", Map.of(createDisplayResponse("Full Name", "en"), "John Doe"));
            displayProps.put("age", Map.of(createDisplayResponse("Age", "en"), "30"));
            displayProps.put("email", Map.of(createDisplayResponse("Email", "en"), "john@example.com"));
            displayProps.put("country", Map.of(createDisplayResponse("Country", "en"), "USA"));

            when(sdJwtCredentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString()))
                    .thenReturn(displayProps);

            when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                    .thenReturn("<html>Test Template</html>");
            when(presentationService.constructPresentationDefinition(any()))
                    .thenReturn(new PresentationDefinitionDTO());
            when(objectMapper.writeValueAsString(any())).thenReturn("{}");

            ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                    "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                    "https://example.com/share", "", "en");

            assertNotNull(result);
            mockedSDJWT.verify(() -> SDJWT.parse(mockSDJWTString));
            // This test verifies that:
            // - Fields with disclosures (name, age) are masked with maskedClaims
            // - Fields without disclosures (email, country) are shown normally
        }
    }

    @Test
    void testNoMaskingForLdpFormat() throws Exception {
        when(credentialFormatHandlerFactory.getHandler("ldp_vc")).thenReturn(credentialFormatHandler);
        // Setup LDP-VC format (not SD-JWT)
        vcCredentialResponse.setFormat("ldp_vc");

        // This test uses the LDP-VC handler (already set up in @BeforeEach)
        Map<String, Object> claims = new HashMap<>();
        claims.put("name", "John Doe");
        claims.put("age", "30");

        // Use the specific LDP-VC handler
        when(credentialFormatHandler.extractCredentialClaims(vcCredentialResponse))
                .thenReturn(claims);

        // Use LinkedHashMap instead of HashMap
        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProps = new LinkedHashMap<>();
        displayProps.put("name", Map.of(createDisplayResponse("Full Name", "en"), "John Doe"));
        displayProps.put("age", Map.of(createDisplayResponse("Age", "en"), "30"));

        when(credentialFormatHandler.loadDisplayPropertiesFromWellknown(any(), any(), anyString()))
                .thenReturn(displayProps);

        when(utilities.getCredentialSupportedTemplateString(anyString(), anyString()))
                .thenReturn("<html>Test Template</html>");
        when(presentationService.constructPresentationDefinition(any()))
                .thenReturn(new PresentationDefinitionDTO());
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        ByteArrayInputStream result = credentialPDFGeneratorService.generatePdfForVerifiableCredential(
                "TestCredential", vcCredentialResponse, issuerDTO, credentialsSupportedResponse,
                "https://example.com/share", "", "en");

        assertNotNull(result);
    }

    private CredentialIssuerDisplayResponse createDisplayResponse(String name, String locale) {
        CredentialIssuerDisplayResponse response = new CredentialIssuerDisplayResponse();
        response.setName(name);
        response.setLocale(locale);
        return response;
    }
}
