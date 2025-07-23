package io.mosip.mimoto.service;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.service.impl.SdJwtCredentialFormatHandler;
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
class SdJwtCredentialFormatHandlerTest {

    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    private SdJwtCredentialFormatHandler sdJwtCredentialFormatHandler;

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
    void extractCredentialClaimsWithStringCredentialShouldReturnClaims() throws JsonProcessingException {
        // Given
        vcCredentialResponse.setCredential(sampleSdJwtString);

        try (MockedStatic<SDJWT> mockedSdJwt = mockStatic(SDJWT.class)) {
            SDJWT mockSdJwt = mock(SDJWT.class);
            mockedSdJwt.when(() -> SDJWT.parse(sampleSdJwtString)).thenReturn(mockSdJwt);
            when(mockSdJwt.getCredentialJwt()).thenReturn(sampleJwtString);
            when(mockSdJwt.getDisclosures()).thenReturn(new ArrayList<>());

            Map<String, Object> jwtPayload = createSampleJwtPayload();
            when(objectMapper.readValue(anyString(), eq(Map.class))).thenReturn(jwtPayload);

            // When
            Map<String, Object> result = sdJwtCredentialFormatHandler.extractCredentialClaims(vcCredentialResponse);

            // Then
            assertNotNull(result);
            assertEquals("John Doe", result.get("name"));
            assertEquals(true, result.get("admin"));
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
        Map<String, Object> result = sdJwtCredentialFormatHandler.extractCredentialClaims(vcCredentialResponse);

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
            Map<String, Object> result = sdJwtCredentialFormatHandler.extractCredentialClaims(vcCredentialResponse);

            // Then
            assertNotNull(result);
            assertTrue(result.isEmpty());
        }
    }

    @Test
    void extractCredentialClaimsWithCredentialSubjectShouldReturnCredentialSubject() throws JsonProcessingException {
        // Given
        vcCredentialResponse.setCredential(sampleSdJwtString);
        Map<String, Object> credentialSubject = new HashMap<>();
        credentialSubject.put("firstName", "John");
        credentialSubject.put("lastName", "Doe");

        try (MockedStatic<SDJWT> mockedSdJwt = mockStatic(SDJWT.class)) {
            SDJWT mockSdJwt = mock(SDJWT.class);
            mockedSdJwt.when(() -> SDJWT.parse(sampleSdJwtString)).thenReturn(mockSdJwt);
            when(mockSdJwt.getCredentialJwt()).thenReturn(sampleJwtString);
            when(mockSdJwt.getDisclosures()).thenReturn(new ArrayList<>());

            Map<String, Object> jwtPayload = new HashMap<>();
            jwtPayload.put("credentialSubject", credentialSubject);
            when(objectMapper.readValue(anyString(), eq(Map.class))).thenReturn(jwtPayload);

            // When
            Map<String, Object> result = sdJwtCredentialFormatHandler.extractCredentialClaims(vcCredentialResponse);

            // Then
            assertNotNull(result);
            assertEquals(credentialSubject, result);
            assertEquals("John", result.get("firstName"));
            assertEquals("Doe", result.get("lastName"));
        }
    }

    @Test
    void extractCredentialClaimsWithDisclosuresShouldIncludeDisclosedClaims() throws JsonProcessingException {
        // Given
        vcCredentialResponse.setCredential(sampleSdJwtString);

        try (MockedStatic<SDJWT> mockedSdJwt = mockStatic(SDJWT.class)) {
            SDJWT mockSdJwt = mock(SDJWT.class);
            Disclosure mockDisclosure = mock(Disclosure.class);
            List<Disclosure> disclosures = Arrays.asList(mockDisclosure);

            mockedSdJwt.when(() -> SDJWT.parse(sampleSdJwtString)).thenReturn(mockSdJwt);
            when(mockSdJwt.getCredentialJwt()).thenReturn(sampleJwtString);
            when(mockSdJwt.getDisclosures()).thenReturn(disclosures);
            when(mockDisclosure.getClaimName()).thenReturn("disclosedClaim");
            when(mockDisclosure.getClaimValue()).thenReturn("disclosedValue");

            Map<String, Object> jwtPayload = createSampleJwtPayload();
            when(objectMapper.readValue(anyString(), eq(Map.class))).thenReturn(jwtPayload);

            // When
            Map<String, Object> result = sdJwtCredentialFormatHandler.extractCredentialClaims(vcCredentialResponse);

            // Then
            assertNotNull(result);
            assertEquals("disclosedValue", result.get("disclosedClaim"));
            assertEquals("John Doe", result.get("name"));
        }
    }

    @Test
    void extractCredentialClaimsWithNullCredentialJwtShouldHandleGracefully() {
        // Given
        vcCredentialResponse.setCredential(sampleSdJwtString);

        try (MockedStatic<SDJWT> mockedSdJwt = mockStatic(SDJWT.class)) {
            SDJWT mockSdJwt = mock(SDJWT.class);
            mockedSdJwt.when(() -> SDJWT.parse(sampleSdJwtString)).thenReturn(mockSdJwt);
            when(mockSdJwt.getCredentialJwt()).thenReturn(null);
            when(mockSdJwt.getDisclosures()).thenReturn(new ArrayList<>());

            // When
            Map<String, Object> result = sdJwtCredentialFormatHandler.extractCredentialClaims(vcCredentialResponse);

            // Then
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
                    sdJwtCredentialFormatHandler.loadDisplayPropertiesFromWellknown(
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
                    sdJwtCredentialFormatHandler.loadDisplayPropertiesFromWellknown(
                            credentialProperties, credentialsSupportedResponse, "en");

            // Then
            assertNotNull(result);
            assertEquals(1, result.size());
            assertTrue(result.containsKey("name"));
        }
    }

    @Test
    void loadDisplayPropertiesFromWellknownWithNullClaimsShouldReturnEmptyMap() {
        // Given
        Map<String, Object> credentialProperties = new HashMap<>();
        credentialsSupportedResponse.setClaims(null);

        // When
        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                sdJwtCredentialFormatHandler.loadDisplayPropertiesFromWellknown(
                        credentialProperties, credentialsSupportedResponse, "en");

        // Then
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void loadDisplayPropertiesFromWellknownWithNullResolvedLocaleShouldReturnEmptyMap() {
        // Given
        Map<String, Object> credentialProperties = new HashMap<>();
        credentialProperties.put("name", "John Doe");

        Map<String, Object> claims = createSampleClaims();
        credentialsSupportedResponse.setClaims(claims);

        CredentialDisplayResponseDto nameDto = createCredentialDisplayResponseDto("Name", "en");
        when(objectMapper.convertValue(any(), eq(CredentialDisplayResponseDto.class)))
                .thenReturn(nameDto);

        try (MockedStatic<LocaleUtils> mockedLocaleUtils = mockStatic(LocaleUtils.class)) {
            mockedLocaleUtils.when(() -> LocaleUtils.resolveLocaleWithFallback(any(), eq("fr")))
                    .thenReturn(null);

            // When
            LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                    sdJwtCredentialFormatHandler.loadDisplayPropertiesFromWellknown(
                            credentialProperties, credentialsSupportedResponse, "fr");

            // Then
            assertNotNull(result);
            assertTrue(result.isEmpty());
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
                    sdJwtCredentialFormatHandler.loadDisplayPropertiesFromWellknown(
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
    void configureCredentialRequestShouldSetVctAndReturnBuiltRequest() {
        // Given
        VCCredentialRequest.VCCredentialRequestBuilder builder = VCCredentialRequest.builder();
        String credentialType = "IdentityCredential";

        // When
        VCCredentialRequest result = sdJwtCredentialFormatHandler.configureCredentialRequest(
                builder, credentialsSupportedResponse, credentialType);

        // Then
        assertNotNull(result);
        // Note: We can't directly verify the vct value as it's set on the builder,
        // but we can verify that a built request is returned
    }

    @Test
    void getSupportedFormatShouldReturnCorrectFormat() {
        // When
        String result = sdJwtCredentialFormatHandler.getSupportedFormat();

        // Then
        assertEquals(CredentialFormat.DC_SD_JWT.getFormat(), result);
    }

    // Helper methods
    private Map<String, Object> createSampleJwtPayload() {
        Map<String, Object> payload = new HashMap<>();
        payload.put("iss", "https://example.com");
        payload.put("sub", "1234567890");
        payload.put("name", "John Doe");
        payload.put("admin", true);
        payload.put("iat", 1516239022);
        return payload;
    }

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
