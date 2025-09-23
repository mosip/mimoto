package io.mosip.mimoto.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.dto.*;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.dto.openid.presentation.*;
import io.mosip.mimoto.exception.DecryptionException;
import io.mosip.mimoto.exception.InvalidIssuerIdException;
import io.mosip.mimoto.model.CredentialMetadata;
import io.mosip.mimoto.model.VerifiableCredential;
import io.mosip.mimoto.repository.WalletCredentialsRepository;
import io.mosip.mimoto.service.impl.CredentialMatchingServiceImpl;
import io.mosip.mimoto.util.EncryptionDecryptionUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialMatchingServiceTest {

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private WalletCredentialsRepository walletCredentialsRepository;

    @Mock
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    @Mock
    private IssuersService issuersService;

    @InjectMocks
    private CredentialMatchingServiceImpl credentialMatchingService;

    private ObjectMapper realObjectMapper;
    private String testWalletId;
    private String testBase64Key;
    private PresentationDefinitionDTO testPresentationDefinition;

    @BeforeEach
    void setUp() {
        realObjectMapper = new ObjectMapper();
        testWalletId = "test-wallet-id";
        testBase64Key = "test-base64-key";
        testPresentationDefinition = createTestPresentationDefinition();
    }

    @Test
    void shouldThrowExceptionWhenWalletIdIsNull() {
        // When & Then
        assertThatThrownBy(() -> credentialMatchingService.getMatchingCredentials(testPresentationDefinition, null, testBase64Key)).isInstanceOf(IllegalArgumentException.class).hasMessage("Wallet ID cannot be null or empty");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "  ", "\t", "\n"})
    void shouldThrowExceptionWhenWalletIdIsEmptyOrWhitespace(String walletId) {
        // When & Then
        assertThatThrownBy(() -> credentialMatchingService.getMatchingCredentials(testPresentationDefinition, walletId, testBase64Key)).isInstanceOf(IllegalArgumentException.class).hasMessage("Wallet ID cannot be null or empty");
    }

    @Test
    void shouldThrowExceptionWhenBase64KeyIsNull() {
        // When & Then
        assertThatThrownBy(() -> credentialMatchingService.getMatchingCredentials(testPresentationDefinition, testWalletId, null)).isInstanceOf(IllegalArgumentException.class).hasMessage("Base64 key cannot be null or empty");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "  ", "\t", "\n"})
    void shouldThrowExceptionWhenBase64KeyIsEmptyOrWhitespace(String base64Key) {
        // When & Then
        assertThatThrownBy(() -> credentialMatchingService.getMatchingCredentials(testPresentationDefinition, testWalletId, base64Key)).isInstanceOf(IllegalArgumentException.class).hasMessage("Base64 key cannot be null or empty");
    }

    @Test
    void shouldThrowExceptionWhenPresentationDefinitionIsNull() {
        // When & Then
        assertThatThrownBy(() -> credentialMatchingService.getMatchingCredentials(null, testWalletId, testBase64Key)).isInstanceOf(IllegalArgumentException.class).hasMessage("Presentation definition cannot be null");
    }

    @Test
    void shouldThrowExceptionWhenInputDescriptorsIsNull() {
        // Given
        PresentationDefinitionDTO presentationDefinition = PresentationDefinitionDTO.builder().id("test-id").inputDescriptors(null).build();

        // When & Then
        assertThatThrownBy(() -> credentialMatchingService.getMatchingCredentials(presentationDefinition, testWalletId, testBase64Key)).isInstanceOf(IllegalArgumentException.class).hasMessage("Presentation definition must contain at least one input descriptor");
    }

    @Test
    void shouldThrowExceptionWhenInputDescriptorsIsEmpty() {
        // Given
        PresentationDefinitionDTO presentationDefinition = PresentationDefinitionDTO.builder().id("test-id").inputDescriptors(Collections.emptyList()).build();

        // When & Then
        assertThatThrownBy(() -> credentialMatchingService.getMatchingCredentials(presentationDefinition, testWalletId, testBase64Key)).isInstanceOf(IllegalArgumentException.class).hasMessage("Presentation definition must contain at least one input descriptor");
    }

    @Test
    void shouldThrowExceptionWhenInputDescriptorHasNullId() {
        // Given
        InputDescriptorDTO inputDescriptor = InputDescriptorDTO.builder().id(null).build();
        PresentationDefinitionDTO presentationDefinition = PresentationDefinitionDTO.builder().id("test-id").inputDescriptors(List.of(inputDescriptor)).build();

        // When & Then
        assertThatThrownBy(() -> credentialMatchingService.getMatchingCredentials(presentationDefinition, testWalletId, testBase64Key)).isInstanceOf(IllegalArgumentException.class).hasMessage("Input descriptor at index 0 must have a valid ID");
    }

    @Test
    void shouldThrowExceptionWhenInputDescriptorHasEmptyId() {
        // Given
        InputDescriptorDTO inputDescriptor = InputDescriptorDTO.builder().id("   ").build();
        PresentationDefinitionDTO presentationDefinition = PresentationDefinitionDTO.builder().id("test-id").inputDescriptors(List.of(inputDescriptor)).build();

        // When & Then
        assertThatThrownBy(() -> credentialMatchingService.getMatchingCredentials(presentationDefinition, testWalletId, testBase64Key)).isInstanceOf(IllegalArgumentException.class).hasMessage("Input descriptor at index 0 must have a valid ID");
    }

    @Test
    void shouldReturnEmptyResponseWhenNoCredentialsFound() throws Exception {
        // Given
        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(Collections.emptyList());

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(testPresentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).isEmpty();
        assertThat(result.getCredentials()).isEmpty();
        assertThat(result.getMatchingCredentialsResponse().getMissingClaims()).isNotEmpty();
    }

    @Test
    void shouldSuccessfullyMatchCredentialsAndReturnResponse() throws Exception {
        // Given
        VerifiableCredential walletCredential = createTestVerifiableCredential();
        VCCredentialResponse vcResponse = createTestVCCredentialResponse();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(vcResponse);

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(decryptedCredentialJson, VCCredentialResponse.class)).thenReturn(vcResponse);
        when(objectMapper.convertValue(any(), eq(VCCredentialProperties.class))).thenReturn(createTestVCCredentialProperties());
        when(issuersService.getIssuerConfig(anyString(), anyString())).thenReturn(null); // Return null to use default values

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(testPresentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).hasSize(1);
        assertThat(result.getCredentials()).hasSize(1);
        assertThat(result.getMatchingCredentialsResponse().getMissingClaims()).isEmpty();

        SelectableCredentialDTO availableCredential = result.getMatchingCredentialsResponse().getAvailableCredentials().get(0);
        assertThat(availableCredential.getCredentialId()).isEqualTo("test-credential-id");
        assertThat(availableCredential.getFormat()).isEqualTo(CredentialFormat.LDP_VC.getFormat());
        assertThat(availableCredential.getCredentialTypeDisplayName()).isEqualTo("Unknown Credential");
    }

    @Test
    void shouldHandleDecryptionFailuresGracefully() throws Exception {
        // Given
        VerifiableCredential walletCredential = createTestVerifiableCredential();
        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenThrow(new DecryptionException("DECRYPTION_ERROR", "Decryption failed"));

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(testPresentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).isEmpty();
        assertThat(result.getCredentials()).isEmpty();
        assertThat(result.getMatchingCredentialsResponse().getMissingClaims()).isNotEmpty();
    }

    @Test
    void shouldHandleJsonParsingFailuresGracefully() throws Exception {
        // Given
        VerifiableCredential walletCredential = createTestVerifiableCredential();
        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn("invalid-json");
        when(objectMapper.readValue("invalid-json", VCCredentialResponse.class)).thenThrow(new JsonProcessingException("Invalid JSON") {
        });

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(testPresentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).isEmpty();
        assertThat(result.getCredentials()).isEmpty();
        assertThat(result.getMatchingCredentialsResponse().getMissingClaims()).isNotEmpty();
    }

    @Test
    void shouldHandleIssuerServiceFailuresGracefully() throws Exception {
        // Given
        VerifiableCredential walletCredential = createTestVerifiableCredential();
        VCCredentialResponse vcResponse = createTestVCCredentialResponse();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(vcResponse);

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(decryptedCredentialJson, VCCredentialResponse.class)).thenReturn(vcResponse);
        when(objectMapper.convertValue(any(), eq(VCCredentialProperties.class))).thenReturn(createTestVCCredentialProperties());
        when(issuersService.getIssuerConfig(anyString(), anyString())).thenThrow(new InvalidIssuerIdException());

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(testPresentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).hasSize(1);
        SelectableCredentialDTO availableCredential = result.getMatchingCredentialsResponse().getAvailableCredentials().get(0);
        assertThat(availableCredential.getCredentialTypeDisplayName()).isEqualTo("Unknown Credential");
        assertThat(availableCredential.getCredentialTypeLogo()).isNull();
    }

    @Test
    void shouldMatchLdpVcFormatCredentials() throws Exception {
        // Given
        VerifiableCredential walletCredential = createTestVerifiableCredential();
        VCCredentialResponse vcResponse = createTestVCCredentialResponse();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(vcResponse);

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(decryptedCredentialJson, VCCredentialResponse.class)).thenReturn(vcResponse);
        when(objectMapper.convertValue(any(), eq(VCCredentialProperties.class))).thenReturn(createTestVCCredentialProperties());
        when(issuersService.getIssuerConfig(anyString(), anyString())).thenReturn(null); // Return null to use default values

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(testPresentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).hasSize(1);
    }

    @Test
    void shouldNotMatchCredentialsWithDifferentFormat() throws Exception {
        // Given
        VerifiableCredential walletCredential = createTestVerifiableCredential();
        VCCredentialResponse vcResponse = VCCredentialResponse.builder().format("vc+sd-jwt").credential("test-credential").build();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(vcResponse);

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(decryptedCredentialJson, VCCredentialResponse.class)).thenReturn(vcResponse);

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(testPresentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).isEmpty();
        assertThat(result.getMatchingCredentialsResponse().getMissingClaims()).isNotEmpty();
    }

    @Test
    void shouldMatchCredentialsWithProofTypeConstraints() throws Exception {
        // Given
        Map<String, Map<String, List<String>>> format = Map.of("ldp_vc", Map.of("proof_type", List.of("Ed25519Signature2020")));
        InputDescriptorDTO inputDescriptor = InputDescriptorDTO.builder().id("test-descriptor").format(format).build();
        PresentationDefinitionDTO presentationDefinition = PresentationDefinitionDTO.builder().id("test-id").inputDescriptors(List.of(inputDescriptor)).build();

        VerifiableCredential walletCredential = createTestVerifiableCredential();
        VCCredentialResponse vcResponse = createTestVCCredentialResponse();
        VCCredentialProperties vcProperties = createTestVCCredentialProperties();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(vcResponse);

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(decryptedCredentialJson, VCCredentialResponse.class)).thenReturn(vcResponse);
        when(objectMapper.convertValue(any(), eq(VCCredentialProperties.class))).thenReturn(vcProperties);
        when(issuersService.getIssuerConfig(anyString(), anyString())).thenReturn(null); // Return null to use default values

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(presentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).hasSize(1);
    }

    @Test
    void shouldNotMatchCredentialsWithDifferentProofType() throws Exception {
        // Given
        Map<String, Map<String, List<String>>> format = Map.of("ldp_vc", Map.of("proof_type", List.of("DifferentProofType")));
        InputDescriptorDTO inputDescriptor = InputDescriptorDTO.builder().id("test-descriptor").format(format).build();
        PresentationDefinitionDTO presentationDefinition = PresentationDefinitionDTO.builder().id("test-id").inputDescriptors(List.of(inputDescriptor)).build();

        VerifiableCredential walletCredential = createTestVerifiableCredential();
        VCCredentialResponse vcResponse = createTestVCCredentialResponse();
        VCCredentialProperties vcProperties = createTestVCCredentialProperties();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(vcResponse);

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(decryptedCredentialJson, VCCredentialResponse.class)).thenReturn(vcResponse);
        when(objectMapper.convertValue(any(), eq(VCCredentialProperties.class))).thenReturn(vcProperties);

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(presentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).isEmpty();
    }

    @Test
    void shouldMatchFieldPathsWithSimpleJsonPath() throws Exception {
        // Given
        FieldDTO field = FieldDTO.builder().path(new String[]{"$.credentialSubject.name"}).build();
        ConstraintsDTO constraints = ConstraintsDTO.builder().fields(new FieldDTO[]{field}).build();
        InputDescriptorDTO inputDescriptor = InputDescriptorDTO.builder().id("test-descriptor").constraints(constraints).build();
        PresentationDefinitionDTO presentationDefinition = PresentationDefinitionDTO.builder().id("test-id").inputDescriptors(List.of(inputDescriptor)).build();

        VerifiableCredential walletCredential = createTestVerifiableCredential();
        VCCredentialResponse vcResponse = createTestVCCredentialResponse();
        VCCredentialProperties vcProperties = createTestVCCredentialProperties();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(vcResponse);

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(decryptedCredentialJson, VCCredentialResponse.class)).thenReturn(vcResponse);
        when(objectMapper.convertValue(any(), eq(VCCredentialProperties.class))).thenReturn(vcProperties);
        when(issuersService.getIssuerConfig(anyString(), anyString())).thenReturn(null); // Return null to use default values

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(presentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).hasSize(1);
    }

    @Test
    void shouldMatchFieldPathsWithFilterPattern() throws Exception {
        // Given
        FilterDTO filter = FilterDTO.builder().pattern("John").build();
        FieldDTO field = FieldDTO.builder().path(new String[]{"$.credentialSubject.name"}).filter(filter).build();
        ConstraintsDTO constraints = ConstraintsDTO.builder().fields(new FieldDTO[]{field}).build();
        InputDescriptorDTO inputDescriptor = InputDescriptorDTO.builder().id("test-descriptor").constraints(constraints).build();
        PresentationDefinitionDTO presentationDefinition = PresentationDefinitionDTO.builder().id("test-id").inputDescriptors(List.of(inputDescriptor)).build();

        VerifiableCredential walletCredential = createTestVerifiableCredential();
        VCCredentialResponse vcResponse = createTestVCCredentialResponse();
        VCCredentialProperties vcProperties = createTestVCCredentialProperties();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(vcResponse);

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(decryptedCredentialJson, VCCredentialResponse.class)).thenReturn(vcResponse);
        when(objectMapper.convertValue(any(), eq(VCCredentialProperties.class))).thenReturn(vcProperties);
        when(issuersService.getIssuerConfig(anyString(), anyString())).thenReturn(null); // Return null to use default values

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(presentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).hasSize(1);
    }

    @Test
    void shouldNotMatchFieldPathsWhenFilterPatternDoesNotMatch() throws Exception {
        // Given
        FilterDTO filter = FilterDTO.builder().pattern("NonExistentName").build();
        FieldDTO field = FieldDTO.builder().path(new String[]{"$.credentialSubject.name"}).filter(filter).build();
        ConstraintsDTO constraints = ConstraintsDTO.builder().fields(new FieldDTO[]{field}).build();
        InputDescriptorDTO inputDescriptor = InputDescriptorDTO.builder().id("test-descriptor").constraints(constraints).build();
        PresentationDefinitionDTO presentationDefinition = PresentationDefinitionDTO.builder().id("test-id").inputDescriptors(List.of(inputDescriptor)).build();

        VerifiableCredential walletCredential = createTestVerifiableCredential();
        VCCredentialResponse vcResponse = createTestVCCredentialResponse();
        VCCredentialProperties vcProperties = createTestVCCredentialProperties();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(vcResponse);

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(decryptedCredentialJson, VCCredentialResponse.class)).thenReturn(vcResponse);
        when(objectMapper.convertValue(any(), eq(VCCredentialProperties.class))).thenReturn(vcProperties);

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(presentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).isEmpty();
    }

    @Test
    void shouldExtractClaimsFromInputDescriptors() throws Exception {
        // Given
        FieldDTO field1 = FieldDTO.builder().path(new String[]{"$.credentialSubject.name", "$.credentialSubject.email"}).build();
        FieldDTO field2 = FieldDTO.builder().path(new String[]{"$.credentialSubject.age"}).build();
        ConstraintsDTO constraints = ConstraintsDTO.builder().fields(new FieldDTO[]{field1, field2}).build();
        InputDescriptorDTO inputDescriptor = InputDescriptorDTO.builder().id("test-descriptor").constraints(constraints).build();
        PresentationDefinitionDTO presentationDefinition = PresentationDefinitionDTO.builder().id("test-id").inputDescriptors(List.of(inputDescriptor)).build();

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(Collections.emptyList());

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(presentationDefinition, testWalletId, testBase64Key);

        // Then
        Set<String> missingClaims = result.getMatchingCredentialsResponse().getMissingClaims();
        assertThat(missingClaims).contains("name", "email", "age");
    }

    @Test
    void shouldHandleNullOrEmptyFieldPathsGracefully() throws Exception {
        // Given
        FieldDTO field1 = FieldDTO.builder().path(null).build();
        FieldDTO field2 = FieldDTO.builder().path(new String[]{}).build();
        FieldDTO field3 = FieldDTO.builder().path(new String[]{"$.credentialSubject.name"}).build();
        ConstraintsDTO constraints = ConstraintsDTO.builder().fields(new FieldDTO[]{field1, field2, field3}).build();
        InputDescriptorDTO inputDescriptor = InputDescriptorDTO.builder().id("test-descriptor").constraints(constraints).build();
        PresentationDefinitionDTO presentationDefinition = PresentationDefinitionDTO.builder().id("test-id").inputDescriptors(List.of(inputDescriptor)).build();

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(Collections.emptyList());

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(presentationDefinition, testWalletId, testBase64Key);

        // Then
        Set<String> missingClaims = result.getMatchingCredentialsResponse().getMissingClaims();
        assertThat(missingClaims).contains("name");
    }

    @Test
    void shouldHandleNullCredentialDataGracefully() throws Exception {
        // Given
        VerifiableCredential walletCredential = new VerifiableCredential();
        walletCredential.setId("test-credential-id");
        walletCredential.setWalletId(testWalletId);
        walletCredential.setCredential(null);
        walletCredential.setCredentialMetadata(createTestCredentialMetadata());
        walletCredential.setCreatedAt(Instant.now());
        walletCredential.setUpdatedAt(Instant.now());

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(testPresentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).isEmpty();
        assertThat(result.getCredentials()).isEmpty();
    }

    @Test
    void shouldHandleEmptyDecryptedCredentialGracefully() throws Exception {
        // Given
        VerifiableCredential walletCredential = createTestVerifiableCredential();
        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn("");

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(testPresentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).isEmpty();
        assertThat(result.getCredentials()).isEmpty();
    }

    @Test
    void shouldHandleWhitespaceDecryptedCredentialGracefully() throws Exception {
        // Given
        VerifiableCredential walletCredential = createTestVerifiableCredential();
        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn("   ");

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(testPresentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).isEmpty();
        assertThat(result.getCredentials()).isEmpty();
    }

    @Test
    void shouldHandleMultipleCredentialsWithSomeFailingDecryption() throws Exception {
        // Given
        VerifiableCredential credential1 = createTestVerifiableCredential();
        VerifiableCredential credential2 = createTestVerifiableCredential();
        credential2.setId("test-credential-id-2");

        VCCredentialResponse vcResponse = createTestVCCredentialResponse();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(vcResponse);

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(credential1, credential2));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson).thenThrow(new DecryptionException("DECRYPTION_ERROR", "Decryption failed"));
        when(objectMapper.readValue(decryptedCredentialJson, VCCredentialResponse.class)).thenReturn(vcResponse);
        when(objectMapper.convertValue(any(), eq(VCCredentialProperties.class))).thenReturn(createTestVCCredentialProperties());
        when(issuersService.getIssuerConfig(anyString(), anyString())).thenReturn(null); // Return null to use default values

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(testPresentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).hasSize(1);
        assertThat(result.getCredentials()).hasSize(1);
    }

    @Test
    void shouldHandleDuplicateCredentialIds() throws Exception {
        // Given
        VerifiableCredential credential1 = createTestVerifiableCredential();
        VerifiableCredential credential2 = createTestVerifiableCredential();
        // Same ID as credential1
        credential2.setId("test-credential-id");

        VCCredentialResponse vcResponse = createTestVCCredentialResponse();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(vcResponse);

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(credential1, credential2));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(decryptedCredentialJson, VCCredentialResponse.class)).thenReturn(vcResponse);
        when(objectMapper.convertValue(any(), eq(VCCredentialProperties.class))).thenReturn(createTestVCCredentialProperties());
        when(issuersService.getIssuerConfig(anyString(), anyString())).thenReturn(null); // Return null to use default values

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(testPresentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).hasSize(1);
        assertThat(result.getCredentials()).hasSize(2);
    }

    @Test
    void shouldHandleComplexPresentationDefinitionWithMultipleDescriptors() throws Exception {
        // Given - Create test data that only has 'name' field, missing 'email' field
        VCCredentialProperties vcPropertiesWithPartialData = VCCredentialProperties.builder()
                .proof(VCCredentialResponseProof.builder().type("Ed25519Signature2020").build())
                .credentialSubject(Map.of("name", "John Doe")) // Only name, no email
                .type(List.of("VerifiableCredential", "TestCredential"))
                .build();

        FieldDTO field1 = FieldDTO.builder().path(new String[]{"$.credentialSubject.name"}).build();
        FieldDTO field2 = FieldDTO.builder().path(new String[]{"$.credentialSubject.email"}).build();
        ConstraintsDTO constraints1 = ConstraintsDTO.builder().fields(new FieldDTO[]{field1}).build();
        ConstraintsDTO constraints2 = ConstraintsDTO.builder().fields(new FieldDTO[]{field2}).build();

        InputDescriptorDTO descriptor1 = InputDescriptorDTO.builder().id("descriptor-1").constraints(constraints1).build();
        InputDescriptorDTO descriptor2 = InputDescriptorDTO.builder().id("descriptor-2").constraints(constraints2).build();

        PresentationDefinitionDTO presentationDefinition = PresentationDefinitionDTO.builder().id("complex-test-id").inputDescriptors(List.of(descriptor1, descriptor2)).build();

        VerifiableCredential walletCredential = createTestVerifiableCredential();
        VCCredentialResponse vcResponse = createTestVCCredentialResponse();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(vcResponse);

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(decryptedCredentialJson, VCCredentialResponse.class)).thenReturn(vcResponse);
        when(objectMapper.convertValue(any(), eq(VCCredentialProperties.class))).thenReturn(vcPropertiesWithPartialData);
        when(issuersService.getIssuerConfig(anyString(), anyString())).thenReturn(null); // Return null to use default values

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(presentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).hasSize(1);
        assertThat(result.getCredentials()).hasSize(1);
        // The second descriptor should have missing claims since the test data only contains 'name' but not 'email'
        assertThat(result.getMatchingCredentialsResponse().getMissingClaims()).contains("email");
    }

    @Test
    void shouldHandleMixedCredentialFormatsInWallet() throws Exception {
        // Given
        VerifiableCredential ldpVcCredential = createTestVerifiableCredential();
        VerifiableCredential sdJwtCredential = new VerifiableCredential();
        sdJwtCredential.setId("sd-jwt-credential-id");
        sdJwtCredential.setWalletId(testWalletId);
        sdJwtCredential.setCredential("encrypted-sd-jwt-credential-data");
        sdJwtCredential.setCredentialMetadata(createTestCredentialMetadata());
        sdJwtCredential.setCreatedAt(Instant.now());
        sdJwtCredential.setUpdatedAt(Instant.now());

        VCCredentialResponse ldpVcResponse = createTestVCCredentialResponse();
        VCCredentialResponse sdJwtResponse = VCCredentialResponse.builder().format("vc+sd-jwt").credential("test-sd-jwt-credential").build();

        String ldpVcJson = realObjectMapper.writeValueAsString(ldpVcResponse);
        String sdJwtJson = realObjectMapper.writeValueAsString(sdJwtResponse);

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(ldpVcCredential, sdJwtCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(ldpVcJson).thenReturn(sdJwtJson);
        when(objectMapper.readValue(ldpVcJson, VCCredentialResponse.class)).thenReturn(ldpVcResponse);
        when(objectMapper.readValue(sdJwtJson, VCCredentialResponse.class)).thenReturn(sdJwtResponse);
        when(objectMapper.convertValue(any(), eq(VCCredentialProperties.class))).thenReturn(createTestVCCredentialProperties());
        when(issuersService.getIssuerConfig(anyString(), anyString())).thenReturn(null); // Return null to use default values

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(testPresentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).hasSize(1);
        assertThat(result.getCredentials()).hasSize(2);
    }

    @Test
    void shouldHandleSdJwtFormatCredentials() throws Exception {
        // Given - Create a presentation definition that matches SD-JWT structure
        FieldDTO field = FieldDTO.builder().path(new String[]{"$.name"}).build(); // SD-JWT has direct field access
        ConstraintsDTO constraints = ConstraintsDTO.builder().fields(new FieldDTO[]{field}).build();
        InputDescriptorDTO inputDescriptor = InputDescriptorDTO.builder().id("sd-jwt-descriptor").format(null).constraints(constraints).build();
        PresentationDefinitionDTO sdJwtPresentationDefinition = PresentationDefinitionDTO.builder().id("sd-jwt-test-id").inputDescriptors(List.of(inputDescriptor)).build();

        VerifiableCredential walletCredential = createTestVerifiableCredential();
        VCCredentialResponse sdJwtResponse = VCCredentialResponse.builder().format("vc+sd-jwt").credential("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0LXVzZXIiLCJuYW1lIjoiSm9obiBEb2UifQ.signature~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgIm5hbWUiLCAiSm9obiBEb2UiXQ").build();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(sdJwtResponse);

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(decryptedCredentialJson, VCCredentialResponse.class)).thenReturn(sdJwtResponse);
        when(objectMapper.convertValue(any(), eq(String.class))).thenReturn("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0LXVzZXIiLCJuYW1lIjoiSm9obiBEb2UifQ.signature~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgIm5hbWUiLCAiSm9obiBEb2UiXQ");
        when(issuersService.getIssuerConfig(anyString(), anyString())).thenReturn(null);

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(sdJwtPresentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).hasSize(1);
        assertThat(result.getCredentials()).hasSize(1);

        SelectableCredentialDTO availableCredential = result.getMatchingCredentialsResponse().getAvailableCredentials().get(0);
        assertThat(availableCredential.getFormat()).isEqualTo("vc+sd-jwt");
    }

    @Test
    void shouldHandleInvalidSdJwtFormat() throws Exception {
        // Given
        VerifiableCredential walletCredential = createTestVerifiableCredential();
        VCCredentialResponse sdJwtResponse = VCCredentialResponse.builder().format("vc+sd-jwt").credential("invalid.jwt.format").build();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(sdJwtResponse);

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(decryptedCredentialJson, VCCredentialResponse.class)).thenReturn(sdJwtResponse);

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(testPresentationDefinition, testWalletId, testBase64Key);

        // Then - Should handle gracefully: credential appears in raw list but not in available credentials
        // because SD-JWT processing fails during matching, not during decryption
        assertThat(result).isNotNull();
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).isEmpty();
        assertThat(result.getCredentials()).hasSize(1); // Raw credential is still present
        assertThat(result.getMatchingCredentialsResponse().getMissingClaims()).contains("name");
    }

    @Test
    void shouldMatchComplexJsonPathExpressions() throws Exception {
        // Given
        FieldDTO complexField = FieldDTO.builder().path(new String[]{"$.credentialSubject.address.street", "$.credentialSubject.address.city", "$.credentialSubject.personalDetails.age"}).build();
        ConstraintsDTO constraints = ConstraintsDTO.builder().fields(new FieldDTO[]{complexField}).build();
        InputDescriptorDTO inputDescriptor = InputDescriptorDTO.builder().id("complex-descriptor").format(null).constraints(constraints).build();
        PresentationDefinitionDTO complexPresentationDefinition = PresentationDefinitionDTO.builder().id("complex-test-id").inputDescriptors(List.of(inputDescriptor)).build();

        VCCredentialProperties complexCredentialProperties = VCCredentialProperties.builder().proof(VCCredentialResponseProof.builder().type("Ed25519Signature2020").build()).credentialSubject(Map.of("name", "John Doe", "address", Map.of("street", "123 Main St", "city", "New York"), "personalDetails", Map.of("age", 30))).type(List.of("VerifiableCredential", "AddressCredential")).build();

        VerifiableCredential walletCredential = createTestVerifiableCredential();
        VCCredentialResponse vcResponse = VCCredentialResponse.builder().format(CredentialFormat.LDP_VC.getFormat()).credential(complexCredentialProperties).build();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(vcResponse);

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(decryptedCredentialJson, VCCredentialResponse.class)).thenReturn(vcResponse);
        when(objectMapper.convertValue(any(), eq(VCCredentialProperties.class))).thenReturn(complexCredentialProperties);
        when(issuersService.getIssuerConfig(anyString(), anyString())).thenReturn(null);

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(complexPresentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).hasSize(1);
        assertThat(result.getMatchingCredentialsResponse().getMissingClaims()).isEmpty();
    }

    @Test
    void shouldHandleFilterWithConstValue() throws Exception {
        // Given
        FilterDTO constFilter = FilterDTO.builder().pattern("VerifiableCredential").build();
        FieldDTO fieldWithConstFilter = FieldDTO.builder().path(new String[]{"$.type"}).filter(constFilter).build();
        ConstraintsDTO constraints = ConstraintsDTO.builder().fields(new FieldDTO[]{fieldWithConstFilter}).build();
        InputDescriptorDTO inputDescriptor = InputDescriptorDTO.builder().id("const-filter-descriptor").format(null).constraints(constraints).build();
        PresentationDefinitionDTO presentationDefinition = PresentationDefinitionDTO.builder().id("const-filter-test").inputDescriptors(List.of(inputDescriptor)).build();

        VerifiableCredential walletCredential = createTestVerifiableCredential();
        VCCredentialResponse vcResponse = createTestVCCredentialResponse();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(vcResponse);

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(decryptedCredentialJson, VCCredentialResponse.class)).thenReturn(vcResponse);
        when(objectMapper.convertValue(any(), eq(VCCredentialProperties.class))).thenReturn(createTestVCCredentialProperties());
        when(issuersService.getIssuerConfig(anyString(), anyString())).thenReturn(null);

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(presentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).hasSize(1);
    }

    @Test
    void shouldHandleMultipleProofTypeRequirements() throws Exception {
        // Given
        Map<String, Map<String, List<String>>> format = Map.of("ldp_vc", Map.of("proof_type", List.of("Ed25519Signature2020", "RsaSignature2018")));
        InputDescriptorDTO inputDescriptor = InputDescriptorDTO.builder().id("multi-proof-descriptor").format(format).build();
        PresentationDefinitionDTO presentationDefinition = PresentationDefinitionDTO.builder().id("multi-proof-test").inputDescriptors(List.of(inputDescriptor)).build();

        VerifiableCredential walletCredential = createTestVerifiableCredential();
        VCCredentialResponse vcResponse = createTestVCCredentialResponse();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(vcResponse);

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(decryptedCredentialJson, VCCredentialResponse.class)).thenReturn(vcResponse);
        when(objectMapper.convertValue(any(), eq(VCCredentialProperties.class))).thenReturn(createTestVCCredentialProperties());
        when(issuersService.getIssuerConfig(anyString(), anyString())).thenReturn(null);

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(presentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).hasSize(1);
    }

    @Test
    void shouldHandleEmptyConstraints() throws Exception {
        // Given
        ConstraintsDTO emptyConstraints = ConstraintsDTO.builder().fields(new FieldDTO[]{}).build();
        InputDescriptorDTO inputDescriptor = InputDescriptorDTO.builder().id("empty-constraints-descriptor").format(null).constraints(emptyConstraints).build();
        PresentationDefinitionDTO presentationDefinition = PresentationDefinitionDTO.builder().id("empty-constraints-test").inputDescriptors(List.of(inputDescriptor)).build();

        VerifiableCredential walletCredential = createTestVerifiableCredential();
        VCCredentialResponse vcResponse = createTestVCCredentialResponse();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(vcResponse);

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(decryptedCredentialJson, VCCredentialResponse.class)).thenReturn(vcResponse);
        when(issuersService.getIssuerConfig(anyString(), anyString())).thenReturn(null);

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(presentationDefinition, testWalletId, testBase64Key);

        // Then - Should match since no constraints means no requirements
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).hasSize(1);
        assertThat(result.getMatchingCredentialsResponse().getMissingClaims()).isEmpty();
    }

    @Test
    void shouldHandleNullConstraints() throws Exception {
        // Given
        InputDescriptorDTO inputDescriptor = InputDescriptorDTO.builder().id("null-constraints-descriptor").format(null).constraints(null).build();
        PresentationDefinitionDTO presentationDefinition = PresentationDefinitionDTO.builder().id("null-constraints-test").inputDescriptors(List.of(inputDescriptor)).build();

        VerifiableCredential walletCredential = createTestVerifiableCredential();
        VCCredentialResponse vcResponse = createTestVCCredentialResponse();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(vcResponse);

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(decryptedCredentialJson, VCCredentialResponse.class)).thenReturn(vcResponse);
        when(issuersService.getIssuerConfig(anyString(), anyString())).thenReturn(null);

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(presentationDefinition, testWalletId, testBase64Key);

        // Then - Should match since null constraints means no requirements
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).hasSize(1);
        assertThat(result.getMatchingCredentialsResponse().getMissingClaims()).isEmpty();
    }

    @Test
    void shouldHandleInvalidJsonPathExpressions() throws Exception {
        // Given
        FieldDTO invalidField = FieldDTO.builder().path(new String[]{"invalid.path.expression", "$.validPath"}).build();
        ConstraintsDTO constraints = ConstraintsDTO.builder().fields(new FieldDTO[]{invalidField}).build();
        InputDescriptorDTO inputDescriptor = InputDescriptorDTO.builder().id("invalid-path-descriptor").format(null).constraints(constraints).build();
        PresentationDefinitionDTO presentationDefinition = PresentationDefinitionDTO.builder().id("invalid-path-test").inputDescriptors(List.of(inputDescriptor)).build();

        VerifiableCredential walletCredential = createTestVerifiableCredential();
        VCCredentialResponse vcResponse = createTestVCCredentialResponse();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(vcResponse);

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(decryptedCredentialJson, VCCredentialResponse.class)).thenReturn(vcResponse);
        when(objectMapper.convertValue(any(), eq(VCCredentialProperties.class))).thenReturn(createTestVCCredentialProperties());
        
        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(presentationDefinition, testWalletId, testBase64Key);

        // Then - Should handle gracefully and extract what claims it can
        assertThat(result).isNotNull();
        Set<String> missingClaims = result.getMatchingCredentialsResponse().getMissingClaims();
        assertThat(missingClaims).contains("validPath"); // Should extract this claim
    }

    @Test
    void shouldHandleCircularReferenceInCredentialData() throws Exception {
        // Given
        VerifiableCredential walletCredential = createTestVerifiableCredential();

        // Create a credential with potential circular reference scenario
        Map<String, Object> circularRef = new HashMap<>();
        circularRef.put("self", circularRef); // This could cause issues in some JSON processors
        circularRef.put("name", "John Doe");

        VCCredentialProperties credentialWithCircularRef = VCCredentialProperties.builder().proof(VCCredentialResponseProof.builder().type("Ed25519Signature2020").build()).credentialSubject(circularRef).type(List.of("VerifiableCredential", "TestCredential")).build();

        VCCredentialResponse vcResponse = VCCredentialResponse.builder().format(CredentialFormat.LDP_VC.getFormat()).credential(credentialWithCircularRef).build();
        String decryptedCredentialJson = "{\"format\":\"ldp_vc\",\"credential\":{\"proof\":{\"type\":\"Ed25519Signature2020\"},\"credentialSubject\":{\"name\":\"John Doe\"},\"type\":[\"VerifiableCredential\",\"TestCredential\"]}}";

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(decryptedCredentialJson, VCCredentialResponse.class)).thenReturn(vcResponse);
        when(objectMapper.convertValue(any(), eq(VCCredentialProperties.class))).thenReturn(credentialWithCircularRef);
        when(issuersService.getIssuerConfig(anyString(), anyString())).thenReturn(null);

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(testPresentationDefinition, testWalletId, testBase64Key);

        // Then - Should handle gracefully without infinite loops
        assertThat(result).isNotNull();
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).hasSize(1);
    }

    @Test
    void shouldHandleLargeCredentialDataSet() throws Exception {
        // Given - Create a large number of credentials to test performance and edge cases
        List<VerifiableCredential> largeCredentialSet = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            VerifiableCredential credential = new VerifiableCredential();
            credential.setId("credential-" + i);
            credential.setWalletId(testWalletId);
            credential.setCredential("encrypted-data-" + i);
            credential.setCredentialMetadata(createTestCredentialMetadata());
            credential.setCreatedAt(Instant.now());
            credential.setUpdatedAt(Instant.now());
            largeCredentialSet.add(credential);
        }

        VCCredentialResponse vcResponse = createTestVCCredentialResponse();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(vcResponse);

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(largeCredentialSet);
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(decryptedCredentialJson, VCCredentialResponse.class)).thenReturn(vcResponse);
        when(objectMapper.convertValue(any(), eq(VCCredentialProperties.class))).thenReturn(createTestVCCredentialProperties());
        when(issuersService.getIssuerConfig(anyString(), anyString())).thenReturn(null);

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(testPresentationDefinition, testWalletId, testBase64Key);

        // Then - Should handle large dataset efficiently
        assertThat(result).isNotNull();
        assertThat(result.getCredentials()).hasSize(100);
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).hasSize(100);
    }

    // Helper methods for creating test data

    private PresentationDefinitionDTO createTestPresentationDefinition() {
        FieldDTO field = FieldDTO.builder().path(new String[]{"$.credentialSubject.name"}).build();
        ConstraintsDTO constraints = ConstraintsDTO.builder().fields(new FieldDTO[]{field}).build();
        InputDescriptorDTO inputDescriptor = InputDescriptorDTO.builder().id("test-descriptor").format(null) // No format constraints - should match any format
                .constraints(constraints).build();
        return PresentationDefinitionDTO.builder().id("test-id").inputDescriptors(List.of(inputDescriptor)).build();
    }

    private VerifiableCredential createTestVerifiableCredential() {
        VerifiableCredential credential = new VerifiableCredential();
        credential.setId("test-credential-id");
        credential.setWalletId(testWalletId);
        credential.setCredential("encrypted-credential-data");
        credential.setCredentialMetadata(createTestCredentialMetadata());
        credential.setCreatedAt(Instant.now());
        credential.setUpdatedAt(Instant.now());
        return credential;
    }

    private CredentialMetadata createTestCredentialMetadata() {
        CredentialMetadata metadata = new CredentialMetadata();
        metadata.setIssuerId("test-issuer-id");
        metadata.setCredentialType("test-credential-type");
        return metadata;
    }

    private VCCredentialResponse createTestVCCredentialResponse() {
        return VCCredentialResponse.builder().format(CredentialFormat.LDP_VC.getFormat()).credential(createTestVCCredentialProperties()).build();
    }

    private VCCredentialProperties createTestVCCredentialProperties() {
        VCCredentialResponseProof proof = VCCredentialResponseProof.builder().type("Ed25519Signature2020").build();
        Map<String, Object> credentialSubject = Map.of("name", "John Doe", "email", "john.doe@example.com");
        return VCCredentialProperties.builder().proof(proof).credentialSubject(credentialSubject).type(List.of("VerifiableCredential", "TestCredential")).build();
    }

    private VCCredentialProperties createTestLdpVcWithProof() {
        VCCredentialResponseProof proof = VCCredentialResponseProof.builder().type("Ed25519Signature2020").build();
        Map<String, Object> credentialSubject = Map.of("name", "John Doe", "email", "john.doe@example.com");
        return VCCredentialProperties.builder().proof(proof).credentialSubject(credentialSubject).type(List.of("VerifiableCredential", "TestCredential")).build();
    }

    // ========== COMPREHENSIVE VALIDATION TESTS ==========


    @Test
    void shouldThrowExceptionWhenInputDescriptorIdIsNull() {
        // Given
        InputDescriptorDTO invalidDescriptor = InputDescriptorDTO.builder().id(null).constraints(createTestConstraints()).build();
        PresentationDefinitionDTO invalidPresentationDefinition = PresentationDefinitionDTO.builder().id("test").inputDescriptors(List.of(invalidDescriptor)).build();

        // When & Then
        assertThatThrownBy(() -> credentialMatchingService.getMatchingCredentials(invalidPresentationDefinition, testWalletId, testBase64Key)).isInstanceOf(IllegalArgumentException.class).hasMessage("Input descriptor at index 0 must have a valid ID");
    }

    @Test
    void shouldThrowExceptionWhenInputDescriptorIdIsEmpty() {
        // Given
        InputDescriptorDTO invalidDescriptor = InputDescriptorDTO.builder().id("").constraints(createTestConstraints()).build();
        PresentationDefinitionDTO invalidPresentationDefinition = PresentationDefinitionDTO.builder().id("test").inputDescriptors(List.of(invalidDescriptor)).build();

        // When & Then
        assertThatThrownBy(() -> credentialMatchingService.getMatchingCredentials(invalidPresentationDefinition, testWalletId, testBase64Key)).isInstanceOf(IllegalArgumentException.class).hasMessage("Input descriptor at index 0 must have a valid ID");
    }

    @Test
    void shouldThrowExceptionWhenInputDescriptorIdIsBlank() {
        // Given
        InputDescriptorDTO invalidDescriptor = InputDescriptorDTO.builder().id("   ").constraints(createTestConstraints()).build();
        PresentationDefinitionDTO invalidPresentationDefinition = PresentationDefinitionDTO.builder().id("test").inputDescriptors(List.of(invalidDescriptor)).build();

        // When & Then
        assertThatThrownBy(() -> credentialMatchingService.getMatchingCredentials(invalidPresentationDefinition, testWalletId, testBase64Key)).isInstanceOf(IllegalArgumentException.class).hasMessage("Input descriptor at index 0 must have a valid ID");
    }

    // ========== FORMAT MATCHING TESTS ==========

    @Test
    void shouldMatchLdpVcFormatWithProofType() throws Exception {
        // Given
        Map<String, List<String>> proofTypes = Map.of("proof_type", List.of("Ed25519Signature2020"));
        Map<String, Map<String, List<String>>> format = Map.of("ldp_vc", proofTypes);

        InputDescriptorDTO descriptor = InputDescriptorDTO.builder().id("ldp-vc-descriptor").format(format).constraints(createTestConstraints()).build();
        PresentationDefinitionDTO presentationDefinition = PresentationDefinitionDTO.builder().id("ldp-vc-test").inputDescriptors(List.of(descriptor)).build();

        VCCredentialResponse ldpVcResponse = VCCredentialResponse.builder().format("ldp_vc").credential(createTestLdpVcWithProof()).build();

        VerifiableCredential walletCredential = createTestVerifiableCredential();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(ldpVcResponse);

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(decryptedCredentialJson, VCCredentialResponse.class)).thenReturn(ldpVcResponse);
        when(objectMapper.convertValue(any(), eq(VCCredentialProperties.class))).thenReturn(createTestLdpVcWithProof());
        when(issuersService.getIssuerConfig(anyString(), anyString())).thenReturn(null);

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(presentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).hasSize(1);
        assertThat(result.getCredentials()).hasSize(1);
    }

    @Test
    void shouldNotMatchLdpVcFormatWithWrongProofType() throws Exception {
        // Given
        Map<String, List<String>> proofTypes = Map.of("proof_type", List.of("WrongProofType"));
        Map<String, Map<String, List<String>>> format = Map.of("ldp_vc", proofTypes);

        InputDescriptorDTO descriptor = InputDescriptorDTO.builder().id("ldp-vc-descriptor").format(format).constraints(createTestConstraints()).build();
        PresentationDefinitionDTO presentationDefinition = PresentationDefinitionDTO.builder().id("ldp-vc-test").inputDescriptors(List.of(descriptor)).build();

        VCCredentialResponse ldpVcResponse = VCCredentialResponse.builder().format("ldp_vc").credential(createTestLdpVcWithProof()).build();

        VerifiableCredential walletCredential = createTestVerifiableCredential();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(ldpVcResponse);

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(decryptedCredentialJson, VCCredentialResponse.class)).thenReturn(ldpVcResponse);
        when(objectMapper.convertValue(any(), eq(VCCredentialProperties.class))).thenReturn(createTestLdpVcWithProof());
 
        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(presentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).isEmpty();
        assertThat(result.getCredentials()).hasSize(1);
        assertThat(result.getMatchingCredentialsResponse().getMissingClaims()).contains("name");
    }

    @Test
    void shouldMatchLdpVcFormatWithoutProofTypeRequirement() throws Exception {
        // Given
        Map<String, Map<String, List<String>>> format = Map.of("ldp_vc", Map.of());

        InputDescriptorDTO descriptor = InputDescriptorDTO.builder().id("ldp-vc-descriptor").format(format).constraints(createTestConstraints()).build();
        PresentationDefinitionDTO presentationDefinition = PresentationDefinitionDTO.builder().id("ldp-vc-test").inputDescriptors(List.of(descriptor)).build();

        VCCredentialResponse ldpVcResponse = VCCredentialResponse.builder().format("ldp_vc").credential(createTestLdpVcWithProof()).build();

        VerifiableCredential walletCredential = createTestVerifiableCredential();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(ldpVcResponse);

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(decryptedCredentialJson, VCCredentialResponse.class)).thenReturn(ldpVcResponse);
        when(objectMapper.convertValue(any(), eq(VCCredentialProperties.class))).thenReturn(createTestLdpVcWithProof());
        when(issuersService.getIssuerConfig(anyString(), anyString())).thenReturn(null);

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(presentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).hasSize(1);
        assertThat(result.getCredentials()).hasSize(1);
    }

    @Test
    void shouldNotMatchNonLdpVcFormat() throws Exception {
        // Given
        Map<String, Map<String, List<String>>> format = Map.of("ldp_vc", Map.of());

        InputDescriptorDTO descriptor = InputDescriptorDTO.builder().id("ldp-vc-descriptor").format(format).constraints(createTestConstraints()).build();
        PresentationDefinitionDTO presentationDefinition = PresentationDefinitionDTO.builder().id("ldp-vc-test").inputDescriptors(List.of(descriptor)).build();

        VCCredentialResponse nonLdpVcResponse = VCCredentialResponse.builder().format("vc+sd-jwt").credential("some-credential").build();

        VerifiableCredential walletCredential = createTestVerifiableCredential();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(nonLdpVcResponse);

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(decryptedCredentialJson, VCCredentialResponse.class)).thenReturn(nonLdpVcResponse);
        
        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(presentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).isEmpty();
        assertThat(result.getCredentials()).hasSize(1);
        assertThat(result.getMatchingCredentialsResponse().getMissingClaims()).contains("name");
    }

    // ========== CONSTRAINTS MATCHING TESTS ==========

    @Test
    void shouldMatchConstraintsWithNullFields() throws Exception {
        // Given
        ConstraintsDTO constraints = ConstraintsDTO.builder().fields(null).build();
        InputDescriptorDTO descriptor = InputDescriptorDTO.builder().id("test-descriptor").format(null).constraints(constraints).build();
        PresentationDefinitionDTO presentationDefinition = PresentationDefinitionDTO.builder().id("test").inputDescriptors(List.of(descriptor)).build();

        VerifiableCredential walletCredential = createTestVerifiableCredential();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(createTestVCCredentialResponse());

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(anyString(), eq(VCCredentialResponse.class))).thenReturn(createTestVCCredentialResponse());
        when(issuersService.getIssuerConfig(anyString(), anyString())).thenReturn(null);

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(presentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).hasSize(1);
        assertThat(result.getCredentials()).hasSize(1);
    }

    @Test
    void shouldMatchConstraintsWithEmptyFields() throws Exception {
        // Given
        ConstraintsDTO constraints = ConstraintsDTO.builder().fields(new FieldDTO[0]).build();
        InputDescriptorDTO descriptor = InputDescriptorDTO.builder().id("test-descriptor").format(null).constraints(constraints).build();
        PresentationDefinitionDTO presentationDefinition = PresentationDefinitionDTO.builder().id("test").inputDescriptors(List.of(descriptor)).build();

        VerifiableCredential walletCredential = createTestVerifiableCredential();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(createTestVCCredentialResponse());

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(anyString(), eq(VCCredentialResponse.class))).thenReturn(createTestVCCredentialResponse());
        when(issuersService.getIssuerConfig(anyString(), anyString())).thenReturn(null);

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(presentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).hasSize(1);
        assertThat(result.getCredentials()).hasSize(1);
    }

    @Test
    void shouldMatchConstraintsWithNullPath() throws Exception {
        // Given
        FieldDTO field = FieldDTO.builder().path(null).build();
        ConstraintsDTO constraints = ConstraintsDTO.builder().fields(new FieldDTO[]{field}).build();
        InputDescriptorDTO descriptor = InputDescriptorDTO.builder().id("test-descriptor").format(null).constraints(constraints).build();
        PresentationDefinitionDTO presentationDefinition = PresentationDefinitionDTO.builder().id("test").inputDescriptors(List.of(descriptor)).build();

        VerifiableCredential walletCredential = createTestVerifiableCredential();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(createTestVCCredentialResponse());

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(anyString(), eq(VCCredentialResponse.class))).thenReturn(createTestVCCredentialResponse());
        when(issuersService.getIssuerConfig(anyString(), anyString())).thenReturn(null);

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(presentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).hasSize(1);
        assertThat(result.getCredentials()).hasSize(1);
    }

    @Test
    void shouldMatchConstraintsWithEmptyPath() throws Exception {
        // Given
        FieldDTO field = FieldDTO.builder().path(new String[0]).build();
        ConstraintsDTO constraints = ConstraintsDTO.builder().fields(new FieldDTO[]{field}).build();
        InputDescriptorDTO descriptor = InputDescriptorDTO.builder().id("test-descriptor").format(null).constraints(constraints).build();
        PresentationDefinitionDTO presentationDefinition = PresentationDefinitionDTO.builder().id("test").inputDescriptors(List.of(descriptor)).build();

        VerifiableCredential walletCredential = createTestVerifiableCredential();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(createTestVCCredentialResponse());

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(anyString(), eq(VCCredentialResponse.class))).thenReturn(createTestVCCredentialResponse());
        when(issuersService.getIssuerConfig(anyString(), anyString())).thenReturn(null);

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(presentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).hasSize(1);
        assertThat(result.getCredentials()).hasSize(1);
    }

    // ========== JSON PATH EVALUATION TESTS ==========

    @Test
    void shouldHandleJsonPathWithoutDollarPrefix() throws Exception {
        // Given
        FieldDTO field = FieldDTO.builder().path(new String[]{"credentialSubject.name"}).build();
        ConstraintsDTO constraints = ConstraintsDTO.builder().fields(new FieldDTO[]{field}).build();
        InputDescriptorDTO descriptor = InputDescriptorDTO.builder().id("test-descriptor").format(null).constraints(constraints).build();
        PresentationDefinitionDTO presentationDefinition = PresentationDefinitionDTO.builder().id("test").inputDescriptors(List.of(descriptor)).build();

        VerifiableCredential walletCredential = createTestVerifiableCredential();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(createTestVCCredentialResponse());

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(anyString(), eq(VCCredentialResponse.class))).thenReturn(createTestVCCredentialResponse());
        
        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(presentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).isEmpty();
        assertThat(result.getCredentials()).hasSize(1);
        assertThat(result.getMatchingCredentialsResponse().getMissingClaims()).contains("name");
    }

    // ========== FILTER MATCHING TESTS ==========

    @Test
    void shouldMatchFilterWithNullFilter() throws Exception {
        // Given
        FieldDTO field = FieldDTO.builder().path(new String[]{"$.credentialSubject.name"}).filter(null).build();
        ConstraintsDTO constraints = ConstraintsDTO.builder().fields(new FieldDTO[]{field}).build();
        InputDescriptorDTO descriptor = InputDescriptorDTO.builder().id("test-descriptor").format(null).constraints(constraints).build();
        PresentationDefinitionDTO presentationDefinition = PresentationDefinitionDTO.builder().id("test").inputDescriptors(List.of(descriptor)).build();

        VerifiableCredential walletCredential = createTestVerifiableCredential();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(createTestVCCredentialResponse());

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(anyString(), eq(VCCredentialResponse.class))).thenReturn(createTestVCCredentialResponse());
        when(objectMapper.convertValue(any(), eq(VCCredentialProperties.class))).thenReturn(createTestVCCredentialProperties());
        when(issuersService.getIssuerConfig(anyString(), anyString())).thenReturn(null);

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(presentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).hasSize(1);
        assertThat(result.getCredentials()).hasSize(1);
    }

    @Test
    void shouldMatchFilterWithNullPattern() throws Exception {
        // Given
        FilterDTO filter = FilterDTO.builder().pattern(null).build();
        FieldDTO field = FieldDTO.builder().path(new String[]{"$.credentialSubject.name"}).filter(filter).build();
        ConstraintsDTO constraints = ConstraintsDTO.builder().fields(new FieldDTO[]{field}).build();
        InputDescriptorDTO descriptor = InputDescriptorDTO.builder().id("test-descriptor").format(null).constraints(constraints).build();
        PresentationDefinitionDTO presentationDefinition = PresentationDefinitionDTO.builder().id("test").inputDescriptors(List.of(descriptor)).build();

        VerifiableCredential walletCredential = createTestVerifiableCredential();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(createTestVCCredentialResponse());

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(anyString(), eq(VCCredentialResponse.class))).thenReturn(createTestVCCredentialResponse());
        when(objectMapper.convertValue(any(), eq(VCCredentialProperties.class))).thenReturn(createTestVCCredentialProperties());
        when(issuersService.getIssuerConfig(anyString(), anyString())).thenReturn(null);

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(presentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).hasSize(1);
        assertThat(result.getCredentials()).hasSize(1);
    }

    // ========== CREDENTIAL DATA EXTRACTION TESTS ==========

    @Test
    void shouldHandleCredentialDataWithMapInstance() throws Exception {
        // Given
        Map<String, Object> credentialData = Map.of("credentialSubject", Map.of("name", "John Doe"), "type", List.of("VerifiableCredential"));
        VCCredentialResponse vcResponse = VCCredentialResponse.builder().format("ldp_vc").credential(credentialData).build();

        FieldDTO field = FieldDTO.builder().path(new String[]{"$.credentialSubject.name"}).build();
        ConstraintsDTO constraints = ConstraintsDTO.builder().fields(new FieldDTO[]{field}).build();
        InputDescriptorDTO descriptor = InputDescriptorDTO.builder().id("test-descriptor").format(null).constraints(constraints).build();
        PresentationDefinitionDTO presentationDefinition = PresentationDefinitionDTO.builder().id("test").inputDescriptors(List.of(descriptor)).build();

        VerifiableCredential walletCredential = createTestVerifiableCredential();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(vcResponse);

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(anyString(), eq(VCCredentialResponse.class))).thenReturn(vcResponse);
        when(issuersService.getIssuerConfig(anyString(), anyString())).thenReturn(null);

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(presentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).hasSize(1);
        assertThat(result.getCredentials()).hasSize(1);
    }

    @Test
    void shouldHandleCredentialDataWithNonMapInstance() throws Exception {
        // Given
        VCCredentialProperties credentialProperties = createTestVCCredentialProperties();
        VCCredentialResponse vcResponse = VCCredentialResponse.builder().format("ldp_vc").credential(credentialProperties).build();

        FieldDTO field = FieldDTO.builder().path(new String[]{"$.credentialSubject.name"}).build();
        ConstraintsDTO constraints = ConstraintsDTO.builder().fields(new FieldDTO[]{field}).build();
        InputDescriptorDTO descriptor = InputDescriptorDTO.builder().id("test-descriptor").format(null).constraints(constraints).build();
        PresentationDefinitionDTO presentationDefinition = PresentationDefinitionDTO.builder().id("test").inputDescriptors(List.of(descriptor)).build();

        VerifiableCredential walletCredential = createTestVerifiableCredential();
        String decryptedCredentialJson = realObjectMapper.writeValueAsString(vcResponse);

        when(walletCredentialsRepository.findByWalletIdOrderByCreatedAtDesc(testWalletId)).thenReturn(List.of(walletCredential));
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(testBase64Key))).thenReturn(decryptedCredentialJson);
        when(objectMapper.readValue(anyString(), eq(VCCredentialResponse.class))).thenReturn(vcResponse);
        when(objectMapper.convertValue(any(), eq(VCCredentialProperties.class))).thenReturn(credentialProperties);
        when(issuersService.getIssuerConfig(anyString(), anyString())).thenReturn(null);

        // When
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService.getMatchingCredentials(presentationDefinition, testWalletId, testBase64Key);

        // Then
        assertThat(result).isNotNull();
        assertThat(result.getMatchingCredentialsResponse().getAvailableCredentials()).hasSize(1);
        assertThat(result.getCredentials()).hasSize(1);
    }

    // ========== CLAIMS EXTRACTION TESTS ==========

    @Test
    void shouldExtractClaimsFromInputDescriptorWithNullConstraints() throws Exception {
        // Given
        InputDescriptorDTO descriptor = InputDescriptorDTO.builder().id("test-descriptor").constraints(null).build();

        // When
        Set<String> claims = credentialMatchingService.getMatchingCredentials(createPresentationDefinitionWithDescriptor(descriptor), testWalletId, testBase64Key).getMatchingCredentialsResponse().getMissingClaims();

        // Then
        assertThat(claims).isEmpty();
    }

    @Test
    void shouldExtractClaimsFromInputDescriptorWithNullFields() throws Exception {
        // Given
        ConstraintsDTO constraints = ConstraintsDTO.builder().fields(null).build();
        InputDescriptorDTO descriptor = InputDescriptorDTO.builder().id("test-descriptor").constraints(constraints).build();

        // When
        Set<String> claims = credentialMatchingService.getMatchingCredentials(createPresentationDefinitionWithDescriptor(descriptor), testWalletId, testBase64Key).getMatchingCredentialsResponse().getMissingClaims();

        // Then
        assertThat(claims).isEmpty();
    }

    @Test
    void shouldExtractClaimsFromInputDescriptorWithNullPath() throws Exception {
        // Given
        FieldDTO field = FieldDTO.builder().path(null).build();
        ConstraintsDTO constraints = ConstraintsDTO.builder().fields(new FieldDTO[]{field}).build();
        InputDescriptorDTO descriptor = InputDescriptorDTO.builder().id("test-descriptor").constraints(constraints).build();

        // When
        Set<String> claims = credentialMatchingService.getMatchingCredentials(createPresentationDefinitionWithDescriptor(descriptor), testWalletId, testBase64Key).getMatchingCredentialsResponse().getMissingClaims();

        // Then
        assertThat(claims).isEmpty();
    }

    @Test
    void shouldExtractClaimsFromInputDescriptorWithEmptyPath() throws Exception {
        // Given
        FieldDTO field = FieldDTO.builder().path(new String[0]).build();
        ConstraintsDTO constraints = ConstraintsDTO.builder().fields(new FieldDTO[]{field}).build();
        InputDescriptorDTO descriptor = InputDescriptorDTO.builder().id("test-descriptor").constraints(constraints).build();

        // When
        Set<String> claims = credentialMatchingService.getMatchingCredentials(createPresentationDefinitionWithDescriptor(descriptor), testWalletId, testBase64Key).getMatchingCredentialsResponse().getMissingClaims();

        // Then
        assertThat(claims).isEmpty();
    }

    @Test
    void shouldExtractClaimsFromInputDescriptorWithBlankPath() throws Exception {
        // Given
        FieldDTO field = FieldDTO.builder().path(new String[]{"   "}).build();
        ConstraintsDTO constraints = ConstraintsDTO.builder().fields(new FieldDTO[]{field}).build();
        InputDescriptorDTO descriptor = InputDescriptorDTO.builder().id("test-descriptor").constraints(constraints).build();

        // When
        Set<String> claims = credentialMatchingService.getMatchingCredentials(createPresentationDefinitionWithDescriptor(descriptor), testWalletId, testBase64Key).getMatchingCredentialsResponse().getMissingClaims();

        // Then
        assertThat(claims).isEmpty();
    }

    // ========== HELPER METHODS ==========

    private PresentationDefinitionDTO createPresentationDefinitionWithDescriptor(InputDescriptorDTO descriptor) {
        return PresentationDefinitionDTO.builder().id("test").inputDescriptors(List.of(descriptor)).build();
    }

    private ConstraintsDTO createTestConstraints() {
        FieldDTO field = FieldDTO.builder().path(new String[]{"$.credentialSubject.name"}).build();
        return ConstraintsDTO.builder().fields(new FieldDTO[]{field}).build();
    }

}
