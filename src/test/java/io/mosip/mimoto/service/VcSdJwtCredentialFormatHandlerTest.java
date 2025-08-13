package io.mosip.mimoto.service;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.service.impl.VcSdJwtCredentialFormatHandler;
import io.mosip.mimoto.util.JwtUtils;
import io.mosip.mimoto.util.LocaleUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class VcSdJwtCredentialFormatHandlerTest {

    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    private VcSdJwtCredentialFormatHandler vcSdJwtCredentialFormatHandler;

    private VCCredentialResponse vcCredentialResponse;
    private CredentialsSupportedResponse credentialsSupportedResponse;
    private String sampleSdJwtString;
    private String sampleJwtString;

    @BeforeEach
    void setUp() {
        vcCredentialResponse = new VCCredentialResponse();
        credentialsSupportedResponse = new CredentialsSupportedResponse();

        // Sample SD-JWT string (simplified for testing)
        sampleSdJwtString = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiMTIzNDU2Nzg5MCIsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.invalid";

        // Sample JWT string for payload parsing
        sampleJwtString = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwic3ViIjoiMTIzNDU2Nzg5MCIsIm5hbWUiOiJKb2huIERvZSIsImFkbWluIjp0cnVlLCJpYXQiOjE1MTYyMzkwMjJ9.invalid";
    }

    @Test
    void extractCredentialClaimsWithStringCredentialShouldReturnClaims() {
        vcCredentialResponse.setCredential(sampleSdJwtString);

        try (MockedStatic<SDJWT> mockedSdJwt = mockStatic(SDJWT.class);
             MockedStatic<JwtUtils> mockedJwtUtils = mockStatic(JwtUtils.class)) {

            SDJWT mockSdJwt = mock(SDJWT.class);
            mockedSdJwt.when(() -> SDJWT.parse(sampleSdJwtString)).thenReturn(mockSdJwt);
            when(mockSdJwt.getCredentialJwt()).thenReturn(sampleJwtString);
            when(mockSdJwt.getDisclosures()).thenReturn(new ArrayList<>());

            // Mock JWT payload with credentialSubject
            Map<String, Object> jwtPayload = new HashMap<>();
            Map<String, Object> credentialSubject = new HashMap<>();
            credentialSubject.put("name", "John Doe");
            credentialSubject.put("admin", true);
            jwtPayload.put("credentialSubject", credentialSubject);
            jwtPayload.put("iss", "https://example.com");
            jwtPayload.put("sub", "1234567890");
            jwtPayload.put("iat", 1516239022);

            mockedJwtUtils.when(() -> JwtUtils.parseJwtPayload(sampleJwtString))
                    .thenReturn(jwtPayload);

            Map<String, Object> result = vcSdJwtCredentialFormatHandler.extractCredentialClaims(vcCredentialResponse);

            assertNotNull(result);
            assertEquals("John Doe", result.get("name"));
            assertEquals(true, result.get("admin"));
            // Metadata fields should be removed
            assertFalse(result.containsKey("iss"));
            assertFalse(result.containsKey("sub"));
            assertFalse(result.containsKey("iat"));
        }
    }

    @Test
    void extractCredentialClaimsWithoutCredentialSubjectShouldReturnAllClaims() {
        vcCredentialResponse.setCredential(sampleSdJwtString);

        try (MockedStatic<SDJWT> mockedSdJwt = mockStatic(SDJWT.class);
             MockedStatic<JwtUtils> mockedJwtUtils = mockStatic(JwtUtils.class)) {

            SDJWT mockSdJwt = mock(SDJWT.class);
            mockedSdJwt.when(() -> SDJWT.parse(sampleSdJwtString)).thenReturn(mockSdJwt);
            when(mockSdJwt.getCredentialJwt()).thenReturn(sampleJwtString);
            when(mockSdJwt.getDisclosures()).thenReturn(new ArrayList<>());

            // Mock JWT payload without credentialSubject
            Map<String, Object> jwtPayload = new HashMap<>();
            jwtPayload.put("name", "John Doe");
            jwtPayload.put("admin", true);
            jwtPayload.put("iss", "https://example.com");
            jwtPayload.put("sub", "1234567890");
            jwtPayload.put("iat", 1516239022);

            mockedJwtUtils.when(() -> JwtUtils.parseJwtPayload(sampleJwtString))
                    .thenReturn(jwtPayload);

            Map<String, Object> result = vcSdJwtCredentialFormatHandler.extractCredentialClaims(vcCredentialResponse);

            assertNotNull(result);
            assertEquals("John Doe", result.get("name"));
            assertEquals(true, result.get("admin"));
            // Metadata fields should be removed
            assertFalse(result.containsKey("iss"));
            assertFalse(result.containsKey("sub"));
            assertFalse(result.containsKey("iat"));
        }
    }

    @Test
    void extractCredentialClaimsWithNonStringCredentialShouldReturnEmptyMap() {
        // Given
        vcCredentialResponse.setCredential(new Object());

        // When
        Map<String, Object> result = vcSdJwtCredentialFormatHandler.extractCredentialClaims(vcCredentialResponse);

        // Then
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void extractCredentialClaimsWithInvalidSdJwtShouldReturnEmptyMap() {
        // Given
        vcCredentialResponse.setCredential("invalid-sd-jwt");

        try (MockedStatic<SDJWT> mockedSdJwt = mockStatic(SDJWT.class)) {
            mockedSdJwt.when(() -> SDJWT.parse("invalid-sd-jwt"))
                    .thenThrow(new IllegalArgumentException("Invalid SD-JWT"));

            // When
            Map<String, Object> result = vcSdJwtCredentialFormatHandler.extractCredentialClaims(vcCredentialResponse);

            // Then
            assertNotNull(result);
            assertTrue(result.isEmpty());
        }
    }

    @Test
    void extractCredentialClaimsWithDisclosuresShouldIncludeDisclosedClaims() {
        vcCredentialResponse.setCredential(sampleSdJwtString);

        try (MockedStatic<SDJWT> mockedSdJwt = mockStatic(SDJWT.class);
             MockedStatic<JwtUtils> mockedJwtUtils = mockStatic(JwtUtils.class)) {

            SDJWT mockSdJwt = mock(SDJWT.class);
            Disclosure mockDisclosure = mock(Disclosure.class);
            List<Disclosure> disclosures = Arrays.asList(mockDisclosure);

            mockedSdJwt.when(() -> SDJWT.parse(sampleSdJwtString)).thenReturn(mockSdJwt);
            when(mockSdJwt.getCredentialJwt()).thenReturn(sampleJwtString);
            when(mockSdJwt.getDisclosures()).thenReturn(disclosures);
            when(mockDisclosure.getClaimName()).thenReturn("disclosedClaim");
            when(mockDisclosure.getClaimValue()).thenReturn("disclosedValue");

            // Mock JWT payload
            Map<String, Object> jwtPayload = new HashMap<>();
            jwtPayload.put("name", "John Doe");
            jwtPayload.put("iss", "https://example.com");

            mockedJwtUtils.when(() -> JwtUtils.parseJwtPayload(sampleJwtString))
                    .thenReturn(jwtPayload);

            Map<String, Object> result = vcSdJwtCredentialFormatHandler.extractCredentialClaims(vcCredentialResponse);

            assertNotNull(result);
            assertEquals("John Doe", result.get("name"));
            assertEquals("disclosedValue", result.get("disclosedClaim"));
            // Metadata fields should be removed
            assertFalse(result.containsKey("iss"));
        }
    }

    @Test
    void extractCredentialClaimsWithNullCredentialJwtShouldHandleGracefully() {
        vcCredentialResponse.setCredential(sampleSdJwtString);

        try (MockedStatic<SDJWT> mockedSdJwt = mockStatic(SDJWT.class)) {
            SDJWT mockSdJwt = mock(SDJWT.class);
            mockedSdJwt.when(() -> SDJWT.parse(sampleSdJwtString)).thenReturn(mockSdJwt);
            when(mockSdJwt.getCredentialJwt()).thenReturn(null);
            when(mockSdJwt.getDisclosures()).thenReturn(new ArrayList<>());

            Map<String, Object> result = vcSdJwtCredentialFormatHandler.extractCredentialClaims(vcCredentialResponse);

            assertNotNull(result);
            assertTrue(result.isEmpty());
        }
    }

    @Test
    void loadDisplayPropertiesFromWellknownWithValidDataShouldReturnDisplayProperties() {
        // Given
        Map<String, Object> credentialProperties = new HashMap<>();
        credentialProperties.put("name", "John Doe");
        credentialProperties.put("age", 30);

        Map<String, Object> claims = createSampleClaims();
        credentialsSupportedResponse.setClaims(claims);
        credentialsSupportedResponse.setOrder(Arrays.asList("name", "age"));

        CredentialDisplayResponseDto nameDto = createCredentialDisplayResponseDto("Name", "en");
        CredentialDisplayResponseDto ageDto = createCredentialDisplayResponseDto("Age", "en");

        when(objectMapper.convertValue(any(), eq(CredentialDisplayResponseDto.class)))
                .thenReturn(nameDto, ageDto);

        try (MockedStatic<LocaleUtils> mockedLocaleUtils = mockStatic(LocaleUtils.class)) {
            mockedLocaleUtils.when(() -> LocaleUtils.resolveLocaleWithFallback(any(), eq("en")))
                    .thenReturn("en");
            mockedLocaleUtils.when(() -> LocaleUtils.matchesLocale(eq("en"), eq("en")))
                    .thenReturn(true);

            // When
            LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                    vcSdJwtCredentialFormatHandler.loadDisplayPropertiesFromWellknown(
                            credentialProperties, credentialsSupportedResponse, "en");

            // Then
            assertNotNull(result);
            assertEquals(2, result.size());
            assertTrue(result.containsKey("name"));
            assertTrue(result.containsKey("age"));
        }
    }

    @Test
    void loadDisplayPropertiesFromWellknownWithNestedClaimsShouldHandleCorrectly() {
        // Given
        Map<String, Object> credentialProperties = new HashMap<>();
        credentialProperties.put("name", "John Doe");

        Map<String, Object> nestedClaims = new HashMap<>();
        nestedClaims.put("name", new HashMap<>());

        Map<String, Object> wrappedClaims = new HashMap<>();
        wrappedClaims.put("wrapper", nestedClaims);

        credentialsSupportedResponse.setClaims(wrappedClaims);

        CredentialDisplayResponseDto nameDto = createCredentialDisplayResponseDto("Name", "en");
        when(objectMapper.convertValue(any(), eq(CredentialDisplayResponseDto.class)))
                .thenReturn(nameDto);

        try (MockedStatic<LocaleUtils> mockedLocaleUtils = mockStatic(LocaleUtils.class)) {
            mockedLocaleUtils.when(() -> LocaleUtils.resolveLocaleWithFallback(any(), eq("en")))
                    .thenReturn("en");
            mockedLocaleUtils.when(() -> LocaleUtils.matchesLocale(eq("en"), eq("en")))
                    .thenReturn(true);

            // When
            LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                    vcSdJwtCredentialFormatHandler.loadDisplayPropertiesFromWellknown(
                            credentialProperties, credentialsSupportedResponse, "en");

            // Then
            assertNotNull(result);
            assertEquals(1, result.size());
            assertTrue(result.containsKey("name"));
        }
    }

    @Test
    void loadDisplayPropertiesFromWellknownWithNullClaimsShouldUseConvertedLabel() {
        // Given
        Map<String, Object> credentialProperties = new HashMap<>();
        credentialProperties.put("firstName", "John");
        credentialProperties.put("UINValue", "12345");

        credentialsSupportedResponse.setClaims(null);

        // When
        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                vcSdJwtCredentialFormatHandler.loadDisplayPropertiesFromWellknown(
                        credentialProperties, credentialsSupportedResponse, "en");

        // Then
        assertNotNull(result);
        assertEquals(2, result.size());
        assertTrue(result.containsKey("firstName"));
        assertTrue(result.containsKey("UINValue"));

        // Check that fallback display for "firstName"
        Map<CredentialIssuerDisplayResponse, Object> displayMap = result.get("firstName");
        CredentialIssuerDisplayResponse display = displayMap.keySet().iterator().next();
        assertEquals("First Name", display.getName()); // convertKeyToLabel should convert camelCase to Pascal Case
        assertEquals("en", display.getLocale());
        assertEquals("John", displayMap.get(display));

        // Check fallback display for "UINValue"
        Map<CredentialIssuerDisplayResponse, Object> uinValueDisplayMap = result.get("UINValue");
        CredentialIssuerDisplayResponse uinValueDisplay = uinValueDisplayMap.keySet().iterator().next();
        assertEquals("UIN Value", uinValueDisplay.getName()); // convertKeyToLabel should convert camelCase to Pascal Case
        assertEquals("en", uinValueDisplay.getLocale());
        assertEquals("12345", uinValueDisplayMap.get(uinValueDisplay));

    }

    @Test
    void loadDisplayPropertiesFromWellknownWithNullResolvedLocaleShouldUseConvertedLabel() {
        // Given
        Map<String, Object> credentialProperties = new HashMap<>();
        credentialProperties.put("firstName", "John Doe");

        Map<String, Object> claims = createSampleClaims();
        credentialsSupportedResponse.setClaims(claims);

        CredentialDisplayResponseDto nameDto = createCredentialDisplayResponseDto("firstName", "en");
        when(objectMapper.convertValue(any(), eq(CredentialDisplayResponseDto.class)))
                .thenReturn(nameDto);

        try (MockedStatic<LocaleUtils> mockedLocaleUtils = mockStatic(LocaleUtils.class)) {
            mockedLocaleUtils.when(() -> LocaleUtils.resolveLocaleWithFallback(any(), eq("fr")))
                    .thenReturn(null);

            // When
            LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                    vcSdJwtCredentialFormatHandler.loadDisplayPropertiesFromWellknown(
                            credentialProperties, credentialsSupportedResponse, "fr");

            // Then
            assertNotNull(result);
            assertEquals(1, result.size());
            assertTrue(result.containsKey("firstName"));

            // Check that fallback display was created
            Map<CredentialIssuerDisplayResponse, Object> displayMap = result.get("firstName");
            CredentialIssuerDisplayResponse display = displayMap.keySet().iterator().next();
            assertEquals("First Name", display.getName());
            assertEquals("en", display.getLocale());
        }
    }

    @Test
    void loadDisplayPropertiesFromWellknownWithCustomOrderShouldRespectOrder() {
        // Given
        Map<String, Object> credentialProperties = new HashMap<>();
        credentialProperties.put("name", "John Doe");
        credentialProperties.put("age", 30);

        Map<String, Object> claims = createSampleClaims();
        credentialsSupportedResponse.setClaims(claims);
        credentialsSupportedResponse.setOrder(Arrays.asList("age", "name")); // Custom order

        CredentialDisplayResponseDto nameDto = createCredentialDisplayResponseDto("Name", "en");
        CredentialDisplayResponseDto ageDto = createCredentialDisplayResponseDto("Age", "en");

        when(objectMapper.convertValue(any(), eq(CredentialDisplayResponseDto.class)))
                .thenReturn(nameDto, ageDto);

        try (MockedStatic<LocaleUtils> mockedLocaleUtils = mockStatic(LocaleUtils.class)) {
            mockedLocaleUtils.when(() -> LocaleUtils.resolveLocaleWithFallback(any(), eq("en")))
                    .thenReturn("en");
            mockedLocaleUtils.when(() -> LocaleUtils.matchesLocale(eq("en"), eq("en")))
                    .thenReturn(true);

            // When
            LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                    vcSdJwtCredentialFormatHandler.loadDisplayPropertiesFromWellknown(
                            credentialProperties, credentialsSupportedResponse, "en");

            // Then
            assertNotNull(result);
            assertEquals(2, result.size());
            List<String> keyOrder = new ArrayList<>(result.keySet());
            assertEquals("age", keyOrder.get(0));
            assertEquals("name", keyOrder.get(1));
        }
    }

    @Test
    void loadDisplayPropertiesFromWellknownWithCustomOrderShouldRespectOrderAndAppendAdditionalFieldsNotPresentInWellknownClaimsAtEnd() {
        // Given
        Map<String, Object> credentialProperties = new HashMap<>();
        credentialProperties.put("name", "John Doe");
        credentialProperties.put("age", 30);
        credentialProperties.put("dob", "1990-01-01"); // Additional field not present in well-known claims
        credentialProperties.put("email", "xyz@gmail.com"); // Additional field not present in well-known claims

        Map<String, Object> claims = createSampleClaims();
        credentialsSupportedResponse.setClaims(claims);
        credentialsSupportedResponse.setOrder(Arrays.asList("age", "name")); // Custom order

        CredentialDisplayResponseDto nameDto = createCredentialDisplayResponseDto("Name", "en");
        CredentialDisplayResponseDto ageDto = createCredentialDisplayResponseDto("Age", "en");
        CredentialDisplayResponseDto dobDto = createCredentialDisplayResponseDto("DOB", "en");
        CredentialDisplayResponseDto emailDto = createCredentialDisplayResponseDto("Email", "en");

        when(objectMapper.convertValue(any(), eq(CredentialDisplayResponseDto.class)))
                .thenReturn(nameDto, dobDto, emailDto, ageDto);

        try (MockedStatic<LocaleUtils> mockedLocaleUtils = mockStatic(LocaleUtils.class)) {
            mockedLocaleUtils.when(() -> LocaleUtils.resolveLocaleWithFallback(any(), eq("en")))
                    .thenReturn("en");
            mockedLocaleUtils.when(() -> LocaleUtils.matchesLocale(eq("en"), eq("en")))
                    .thenReturn(true);

            // When
            LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                    vcSdJwtCredentialFormatHandler.loadDisplayPropertiesFromWellknown(
                            credentialProperties, credentialsSupportedResponse, "en");

            // Then
            assertNotNull(result);
            assertEquals(4, result.size());
            List<String> keyOrder = new ArrayList<>(result.keySet());
            assertEquals("age", keyOrder.get(0));
            assertEquals("name", keyOrder.get(1));
            assertEquals("dob", keyOrder.get(2)); // Additional field should be appended at the end
            assertEquals("email", keyOrder.get(3)); // Additional field should be appended at the end
        }
    }

    @Test
    void buildCredentialRequestShouldReturnBuiltRequest() {
        // Given
        VCCredentialRequestProof proof = VCCredentialRequestProof.builder()
                .proofType("jwt")
                .jwt("sample.jwt.token")
                .build();

        credentialsSupportedResponse.setVct("IdentityCredential");

        // When
        VCCredentialRequest result = vcSdJwtCredentialFormatHandler.buildCredentialRequest(
                proof, credentialsSupportedResponse);

        // Then
        assertNotNull(result);
        assertEquals(CredentialFormat.VC_SD_JWT.getFormat(), result.getFormat());
        assertEquals(proof, result.getProof());
        assertEquals("IdentityCredential", result.getVct());
    }

    @Test
    void getSupportedFormatShouldReturnCorrectFormat() {
        // When
        String result = vcSdJwtCredentialFormatHandler.getSupportedFormat();

        // Then
        assertEquals(CredentialFormat.VC_SD_JWT.getFormat(), result);
    }

    // Helper methods
    private Map<String, Object> createSampleClaims() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("name", new HashMap<>());
        claims.put("age", new HashMap<>());
        return claims;
    }

    private CredentialDisplayResponseDto createCredentialDisplayResponseDto(String name, String locale) {
        CredentialDisplayResponseDto dto = new CredentialDisplayResponseDto();
        CredentialIssuerDisplayResponse display = new CredentialIssuerDisplayResponse();
        display.setName(name);
        display.setLocale(locale);
        dto.setDisplay(Arrays.asList(display));
        return dto;
    }
}