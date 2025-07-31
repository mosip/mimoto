package io.mosip.mimoto.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.service.impl.LdpVcCredentialFormatHandler;
import io.mosip.mimoto.util.LocaleUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.MockedStatic;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class LdpVcCredentialFormatHandlerTest {

    @InjectMocks
    private LdpVcCredentialFormatHandler ldpVcCredentialFormatHandler;

    private VCCredentialResponse vcCredentialResponse;
    private VCCredentialProperties vcCredentialProperties;
    private CredentialsSupportedResponse credentialsSupportedResponse;
    private CredentialDefinitionResponseDto credentialDefinition;
    @Spy
    private ObjectMapper objectMapper;


    @BeforeEach
    void setUp() {
        vcCredentialResponse = new VCCredentialResponse();
        vcCredentialProperties = new VCCredentialProperties();
        credentialsSupportedResponse = new CredentialsSupportedResponse();
        credentialDefinition = new CredentialDefinitionResponseDto();
    }

    @Test
    void extractCredentialClaimsWithValidCredentialShouldReturnCredentialSubject() {
        // Given
        Map<String, Object> credentialSubject = new HashMap<>();
        credentialSubject.put("firstName", "John");
        credentialSubject.put("lastName", "Doe");
        credentialSubject.put("dateOfBirth", "1990-01-01");

        vcCredentialProperties.setCredentialSubject(credentialSubject);
        vcCredentialResponse.setCredential(vcCredentialProperties);

        // When
        Map<String, Object> result = ldpVcCredentialFormatHandler.extractCredentialClaims(vcCredentialResponse);

        // Then
        assertNotNull(result);
        assertEquals(3, result.size());
        assertEquals("John", result.get("firstName"));
        assertEquals("Doe", result.get("lastName"));
        assertEquals("1990-01-01", result.get("dateOfBirth"));
    }

    @Test
    void extractCredentialClaimsWithNullCredentialSubjectShouldReturnNull() {
        // Given
        vcCredentialProperties.setCredentialSubject(null);
        vcCredentialResponse.setCredential(vcCredentialProperties);

        // When
        Map<String, Object> result = ldpVcCredentialFormatHandler.extractCredentialClaims(vcCredentialResponse);

        // Then
        assertNull(result);
    }

    @Test
    void extractCredentialClaimsWithEmptyCredentialSubjectShouldReturnEmptyMap() {
        // Given
        Map<String, Object> credentialSubject = new HashMap<>();
        vcCredentialProperties.setCredentialSubject(credentialSubject);
        vcCredentialResponse.setCredential(vcCredentialProperties);

        // When
        Map<String, Object> result = ldpVcCredentialFormatHandler.extractCredentialClaims(vcCredentialResponse);

        // Then
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void loadDisplayPropertiesFromWellknownWithValidDataShouldReturnDisplayProperties() {
        // Given
        Map<String, Object> credentialProperties = new HashMap<>();
        credentialProperties.put("firstName", "John");
        credentialProperties.put("lastName", "Doe");

        Map<String, CredentialDisplayResponseDto> credentialSubjectConfig = createCredentialSubjectConfig();
        credentialDefinition.setCredentialSubject(credentialSubjectConfig);
        credentialsSupportedResponse.setCredentialDefinition(credentialDefinition);
        credentialsSupportedResponse.setOrder(Arrays.asList("firstName", "lastName"));

        try (MockedStatic<LocaleUtils> mockedLocaleUtils = mockStatic(LocaleUtils.class)) {
            mockedLocaleUtils.when(() -> LocaleUtils.resolveLocaleWithFallback(any(), eq("en")))
                    .thenReturn("en");
            mockedLocaleUtils.when(() -> LocaleUtils.matchesLocale(eq("en"), eq("en")))
                    .thenReturn(true);

            // When
            LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                    ldpVcCredentialFormatHandler.loadDisplayPropertiesFromWellknown(
                            credentialProperties, credentialsSupportedResponse, "en");

            // Then
            assertNotNull(result);
            assertEquals(2, result.size());
            assertTrue(result.containsKey("firstName"));
            assertTrue(result.containsKey("lastName"));

            Map<CredentialIssuerDisplayResponse, Object> firstNameMap = result.get("firstName");
            assertNotNull(firstNameMap);
            assertEquals(1, firstNameMap.size());
            assertEquals("John", firstNameMap.values().iterator().next());
        }
    }

    @Test
    void loadDisplayPropertiesFromWellknownWithNullCredentialDefinitionShouldReturnEmptyMap() {
        // Given
        Map<String, Object> credentialProperties = new HashMap<>();
        credentialProperties.put("firstName", "John");

        credentialsSupportedResponse.setCredentialDefinition(null);

        // When
        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                ldpVcCredentialFormatHandler.loadDisplayPropertiesFromWellknown(
                        credentialProperties, credentialsSupportedResponse, "en");

        // Then
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void loadDisplayPropertiesFromWellknownWithNullCredentialSubjectShouldReturnEmptyMap() {
        // Given
        Map<String, Object> credentialProperties = new HashMap<>();
        credentialProperties.put("firstName", "John");

        credentialDefinition.setCredentialSubject(null);
        credentialsSupportedResponse.setCredentialDefinition(credentialDefinition);

        // When
        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                ldpVcCredentialFormatHandler.loadDisplayPropertiesFromWellknown(
                        credentialProperties, credentialsSupportedResponse, "en");

        // Then
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void loadDisplayPropertiesFromWellknownWithNullDisplayConfigMapShouldReturnEmptyMap() {
        // Given
        Map<String, Object> credentialProperties = new HashMap<>();
        credentialProperties.put("firstName", "John");

        credentialDefinition.setCredentialSubject(null);
        credentialsSupportedResponse.setCredentialDefinition(credentialDefinition);

        // When
        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                ldpVcCredentialFormatHandler.loadDisplayPropertiesFromWellknown(
                        credentialProperties, credentialsSupportedResponse, "en");

        // Then
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void loadDisplayPropertiesFromWellknownWithNullResolvedLocaleShouldReturnEmptyMap() {
        // Given
        Map<String, Object> credentialProperties = new HashMap<>();
        credentialProperties.put("firstName", "John");

        Map<String, CredentialDisplayResponseDto> credentialSubjectConfig = createCredentialSubjectConfig();
        credentialDefinition.setCredentialSubject(credentialSubjectConfig);
        credentialsSupportedResponse.setCredentialDefinition(credentialDefinition);

        try (MockedStatic<LocaleUtils> mockedLocaleUtils = mockStatic(LocaleUtils.class)) {
            mockedLocaleUtils.when(() -> LocaleUtils.resolveLocaleWithFallback(any(), eq("fr")))
                    .thenReturn(null);

            // When
            LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                    ldpVcCredentialFormatHandler.loadDisplayPropertiesFromWellknown(
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
        credentialProperties.put("firstName", "John");
        credentialProperties.put("lastName", "Doe");

        Map<String, CredentialDisplayResponseDto> credentialSubjectConfig = createCredentialSubjectConfig();
        credentialDefinition.setCredentialSubject(credentialSubjectConfig);
        credentialsSupportedResponse.setCredentialDefinition(credentialDefinition);
        credentialsSupportedResponse.setOrder(Arrays.asList("lastName", "firstName")); // Custom order

        try (MockedStatic<LocaleUtils> mockedLocaleUtils = mockStatic(LocaleUtils.class)) {
            mockedLocaleUtils.when(() -> LocaleUtils.resolveLocaleWithFallback(any(), eq("en")))
                    .thenReturn("en");
            mockedLocaleUtils.when(() -> LocaleUtils.matchesLocale(eq("en"), eq("en")))
                    .thenReturn(true);

            // When
            LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                    ldpVcCredentialFormatHandler.loadDisplayPropertiesFromWellknown(
                            credentialProperties, credentialsSupportedResponse, "en");

            // Then
            assertNotNull(result);
            assertEquals(2, result.size());
            List<String> keyOrder = new ArrayList<>(result.keySet());
            assertEquals("lastName", keyOrder.get(0));
            assertEquals("firstName", keyOrder.get(1));
        }
    }

    @Test
    void loadDisplayPropertiesFromWellknownWithEmptyOrderShouldUseNaturalOrder() {
        // Given
        Map<String, Object> credentialProperties = new HashMap<>();
        credentialProperties.put("firstName", "John");
        credentialProperties.put("lastName", "Doe");

        Map<String, CredentialDisplayResponseDto> credentialSubjectConfig = createCredentialSubjectConfig();
        credentialDefinition.setCredentialSubject(credentialSubjectConfig);
        credentialsSupportedResponse.setCredentialDefinition(credentialDefinition);
        credentialsSupportedResponse.setOrder(new ArrayList<>()); // Empty order

        try (MockedStatic<LocaleUtils> mockedLocaleUtils = mockStatic(LocaleUtils.class)) {
            mockedLocaleUtils.when(() -> LocaleUtils.resolveLocaleWithFallback(any(), eq("en")))
                    .thenReturn("en");
            mockedLocaleUtils.when(() -> LocaleUtils.matchesLocale(eq("en"), eq("en")))
                    .thenReturn(true);

            // When
            LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                    ldpVcCredentialFormatHandler.loadDisplayPropertiesFromWellknown(
                            credentialProperties, credentialsSupportedResponse, "en");

            // Then
            assertNotNull(result);
            assertEquals(2, result.size());
            assertTrue(result.containsKey("firstName"));
            assertTrue(result.containsKey("lastName"));
        }
    }

    @Test
    void loadDisplayPropertiesFromWellknownWithNullValuesShouldSkipNullValues() {
        // Given
        Map<String, Object> credentialProperties = new HashMap<>();
        credentialProperties.put("firstName", "John");
        credentialProperties.put("lastName", null); // Null value

        Map<String, CredentialDisplayResponseDto> credentialSubjectConfig = createCredentialSubjectConfig();
        credentialDefinition.setCredentialSubject(credentialSubjectConfig);
        credentialsSupportedResponse.setCredentialDefinition(credentialDefinition);

        try (MockedStatic<LocaleUtils> mockedLocaleUtils = mockStatic(LocaleUtils.class)) {
            mockedLocaleUtils.when(() -> LocaleUtils.resolveLocaleWithFallback(any(), eq("en")))
                    .thenReturn("en");
            mockedLocaleUtils.when(() -> LocaleUtils.matchesLocale(eq("en"), eq("en")))
                    .thenReturn(true);

            // When
            LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> result =
                    ldpVcCredentialFormatHandler.loadDisplayPropertiesFromWellknown(
                            credentialProperties, credentialsSupportedResponse, "en");

            // Then
            assertNotNull(result);
            assertEquals(1, result.size()); // Only firstName should be included
            assertTrue(result.containsKey("firstName"));
            assertFalse(result.containsKey("lastName"));
        }
    }

    @Test
    void buildCredentialRequestWithValidCredentialsSupportedResponseShouldReturnConfiguredRequest() {
        // Given
        VCCredentialRequest.VCCredentialRequestBuilder builder = VCCredentialRequest.builder();

        List<String> types = Arrays.asList("VerifiableCredential", "IdentityCredential");
        List<String> context = Arrays.asList("https://www.w3.org/2018/credentials/v1", "https://example.com/contexts/identity/v1");

        credentialDefinition.setType(types);
        credentialDefinition.setContext(context);
        credentialsSupportedResponse.setCredentialDefinition(credentialDefinition);
        credentialsSupportedResponse.setVct("dd");

        String credentialType = "IdentityCredential";
        VCCredentialRequestProof proof = VCCredentialRequestProof.builder()
                .proofType("jwt")
                .jwt("sample.jwt.token")
                .build();

        // When
        VCCredentialRequest result = ldpVcCredentialFormatHandler.buildCredentialRequest(
                proof, credentialsSupportedResponse);

        // Then
        assertNotNull(result);
        assertNotNull(result.getCredentialDefinition());
        assertEquals(types, result.getCredentialDefinition().getType());
        assertEquals(context, result.getCredentialDefinition().getContext());
    }

    @Test
    void buildCredentialRequestWithNullContextShouldUseDefaultContext() {
        // Given
        VCCredentialRequest.VCCredentialRequestBuilder builder = VCCredentialRequest.builder();

        List<String> types = Arrays.asList("VerifiableCredential", "IdentityCredential");

        credentialDefinition.setType(types);
        credentialDefinition.setContext(null); // Null context
        credentialsSupportedResponse.setCredentialDefinition(credentialDefinition);

        String credentialType = "IdentityCredential";
        VCCredentialRequestProof proof = VCCredentialRequestProof.builder()
                .proofType("jwt")  // or whatever proof type you expect
                .jwt("sample.jwt.token")
                .build();

        // When
        VCCredentialRequest result = ldpVcCredentialFormatHandler.buildCredentialRequest(
                proof, credentialsSupportedResponse);

        // Then
        assertNotNull(result);
        assertNotNull(result.getCredentialDefinition());
        assertEquals(types, result.getCredentialDefinition().getType());
        assertEquals(List.of("https://www.w3.org/2018/credentials/v1"), result.getCredentialDefinition().getContext());
    }

    @Test
    void buildCredentialRequestWithEmptyContextShouldUseDefaultContext() {
        // Given
        VCCredentialRequest.VCCredentialRequestBuilder builder = VCCredentialRequest.builder();

        List<String> types = Arrays.asList("VerifiableCredential", "IdentityCredential");

        credentialDefinition.setType(types);
        credentialDefinition.setContext(new ArrayList<>()); // Empty context
        credentialsSupportedResponse.setCredentialDefinition(credentialDefinition);

        String credentialType = "IdentityCredential";
        VCCredentialRequestProof proof = VCCredentialRequestProof.builder()
                .proofType("jwt")  // or whatever proof type you expect
                .jwt("sample.jwt.token")
                .build();

        // When
        VCCredentialRequest result = ldpVcCredentialFormatHandler.buildCredentialRequest(
                proof, credentialsSupportedResponse);

        // Then
        assertNotNull(result);
        assertNotNull(result.getCredentialDefinition());
        assertEquals(types, result.getCredentialDefinition().getType());
        assertEquals(List.of("https://www.w3.org/2018/credentials/v1"), result.getCredentialDefinition().getContext());
    }

    @Test
    void getSupportedFormatShouldReturnLdpVcFormat() {
        // When
        String result = ldpVcCredentialFormatHandler.getSupportedFormat();

        // Then
        assertEquals(CredentialFormat.LDP_VC.getFormat(), result);
    }

    // Helper methods
    private Map<String, CredentialDisplayResponseDto> createCredentialSubjectConfig() {
        Map<String, CredentialDisplayResponseDto> config = new LinkedHashMap<>();

        // Create firstName display config
        CredentialDisplayResponseDto firstNameDto = new CredentialDisplayResponseDto();
        CredentialIssuerDisplayResponse firstNameDisplay = new CredentialIssuerDisplayResponse();
        firstNameDisplay.setName("First Name");
        firstNameDisplay.setLocale("en");
        firstNameDto.setDisplay(List.of(firstNameDisplay));
        config.put("firstName", firstNameDto);

        // Create lastName display config
        CredentialDisplayResponseDto lastNameDto = new CredentialDisplayResponseDto();
        CredentialIssuerDisplayResponse lastNameDisplay = new CredentialIssuerDisplayResponse();
        lastNameDisplay.setName("Last Name");
        lastNameDisplay.setLocale("en");
        lastNameDto.setDisplay(List.of(lastNameDisplay));
        config.put("lastName", lastNameDto);

        return config;
    }
}
