package io.mosip.mimoto.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.dto.*;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.DecryptionException;
import io.mosip.mimoto.exception.InvalidIssuerIdException;
import io.mosip.mimoto.model.CredentialMetadata;
import io.mosip.mimoto.service.impl.CredentialMatchingServiceImpl;
import io.mosip.mimoto.service.impl.OpenID4VPService;
import io.mosip.mimoto.util.EncryptionDecryptionUtil;
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.time.Instant;
import java.util.*;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class CredentialMatchingServiceTest {

    @InjectMocks
    private CredentialMatchingServiceImpl credentialMatchingService;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private WalletCredentialService walletCredentialService;

    @Mock
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    @Mock
    private IssuersService issuersService;

    @Mock
    private OpenID4VPService openID4VPService;

    private VerifiablePresentationSessionData sessionData;
    private String walletId;
    private String base64Key;
    private PresentationDefinition presentationDefinition;
    private List<DecryptedCredentialDTO> walletCredentials;
    private VCCredentialResponse vcCredentialResponse;

    @Before
    public void setUp() throws JsonProcessingException {
        walletId = "test-wallet-id";
        base64Key = "test-base64-key";

        // Setup session data
        sessionData = new VerifiablePresentationSessionData();

        // Setup presentation definition
        presentationDefinition = createMockPresentationDefinition();

        // Setup wallet credentials
        walletCredentials = createMockWalletCredentials();

        // Setup VC credential response
        vcCredentialResponse = createMockVCCredentialResponse();
    }

   // @Test
    public void testGetMatchingCredentials_Success() throws Exception {
        // Arrange
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(presentationDefinition);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(walletCredentials);
        IssuerConfig issuerConfig = createMockIssuerConfig();
        when(issuersService.getIssuerConfig(anyString(), anyString()))
                .thenReturn(issuerConfig);

        // Act
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertNotNull(result.getMatchingCredentialsResponse());
        assertNotNull(result.getMatchingCredentials());
        assertFalse(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());

        verify(openID4VPService).resolvePresentationDefinition(any(), any(), anyBoolean());
        verify(walletCredentialService).getDecryptedCredentials(eq(walletId), any());
        verify(encryptionDecryptionUtil).decryptCredential(anyString(), eq(base64Key));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetMatchingCredentials_NullWalletId() throws Exception {
        // Arrange
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(presentationDefinition);

        // Act
        credentialMatchingService.getMatchingCredentials(sessionData, null, base64Key);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetMatchingCredentials_EmptyWalletId() throws Exception {
        // Arrange
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(presentationDefinition);

        // Act
        credentialMatchingService.getMatchingCredentials(sessionData, "", base64Key);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetMatchingCredentials_NullBase64Key() throws Exception {
        // Arrange
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(presentationDefinition);

        // Act
        credentialMatchingService.getMatchingCredentials(sessionData, walletId, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGetMatchingCredentials_NullPresentationDefinition() throws Exception {
        // Arrange
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(null);

        // Act
        credentialMatchingService.getMatchingCredentials(sessionData, walletId, base64Key);
    }

    @Test
    public void testGetMatchingCredentials_EmptyWalletCredentials() throws Exception {
        // Arrange
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(presentationDefinition);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(Collections.emptyList());

        // Act
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertNotNull(result.getMatchingCredentialsResponse());
        assertTrue(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
        assertTrue(result.getMatchingCredentials().isEmpty());
        assertFalse(result.getMatchingCredentialsResponse().getMissingClaims().isEmpty());
    }

    @Test
    public void testGetMatchingCredentials_DecryptionFailure() throws Exception {
        // Arrange
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(presentationDefinition);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(walletCredentials);

        // Act
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertTrue(result.getMatchingCredentials().isEmpty());
    }

    @Test
    public void testGetMatchingCredentials_IssuerConfigNotFound() throws Exception {
        // Arrange
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(presentationDefinition);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(walletCredentials);


        // Act
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertNotNull(result.getMatchingCredentialsResponse());
        // Should still work but with default credential display name
        if (!result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty()) {
            assertEquals("Unknown Credential",
                    result.getMatchingCredentialsResponse().getAvailableCredentials().get(0).getCredentialTypeDisplayName());
        }
    }

    @Test
    public void testGetMatchingCredentials_WithConstraints() throws Exception {
        // Arrange
        PresentationDefinition pdWithConstraints = createMockPresentationDefinitionWithConstraints();
        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(pdWithConstraints);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(walletCredentials);

        // Act
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        assertNotNull(result.getMatchingCredentialsResponse());
    }

    //@Test
    public void testGetMatchingCredentials_FormatMismatch() throws Exception {
        // Arrange
        PresentationDefinition pdWithFormat = createMockPresentationDefinitionWithSpecificFormat();
        VCCredentialResponse vcWithDifferentFormat = createMockVCCredentialResponseWithDifferentFormat();

        when(openID4VPService.resolvePresentationDefinition(any(), any(), anyBoolean()))
                .thenReturn(pdWithFormat);
        when(walletCredentialService.getDecryptedCredentials(eq(walletId), any()))
                .thenReturn(walletCredentials);
        when(encryptionDecryptionUtil.decryptCredential(anyString(), eq(base64Key)))
                .thenReturn("{\"format\":\"vc+sd-jwt\",\"credential\":\"jwt-token-here\"}");
        when(objectMapper.readValue(anyString(), eq(VCCredentialResponse.class)))
                .thenReturn(vcWithDifferentFormat);

        // Act
        MatchingCredentialsWithWalletDataDTO result = credentialMatchingService
                .getMatchingCredentials(sessionData, walletId, base64Key);

        // Assert
        assertNotNull(result);
        // Should not match due to format mismatch
        assertTrue(result.getMatchingCredentialsResponse().getAvailableCredentials().isEmpty());
    }

    // Helper methods to create mock objects

    private PresentationDefinition createMockPresentationDefinition() {

        Fields field = new Fields(Arrays.asList("$.type"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test-descriptor", null, null, null, constraints);
        PresentationDefinition pd = new PresentationDefinition("test-presentation-definition", Arrays.asList(descriptor), null, null, null);
        return pd;
    }

    private PresentationDefinition createMockPresentationDefinitionWithConstraints() {
        // Field 1: simple path
        Fields field1 = new Fields(Arrays.asList("$.type"), null, null, null, null, null);

        // Field 2: with path and filter
        Filter filter = new Filter("type", "String");
        Fields field2 = new Fields(Arrays.asList("$.credentialSubject.name"), null, null, null, filter, null);

        // Constraints with both fields
        Constraints constraints = new Constraints(Arrays.asList(field1, field2), null);

        // Input Descriptor with constraints
        InputDescriptor descriptor = new InputDescriptor("test-descriptor-with-constraints", null, null, null, constraints);

        // Presentation Definition with descriptor
        PresentationDefinition pd = new PresentationDefinition("test-presentation-definition-with-constraints", Arrays.asList(descriptor), null, null, null);

        return pd;
    }


    private PresentationDefinition createMockPresentationDefinitionWithSpecificFormat() {
        Map<String, Map<String, List<String>>> format = new HashMap<>();
        Map<String, List<String>> ldpVcFormat = new HashMap<>();
        ldpVcFormat.put("proof_type", Arrays.asList("Ed25519Signature2020"));
        format.put("ldp_vc", ldpVcFormat);
        Fields field = new Fields(Arrays.asList("$.type"), null, null, null, null, null);
        Constraints constraints = new Constraints(Collections.singletonList(field), null);
        InputDescriptor descriptor = new InputDescriptor("test-descriptor", null, null, format, constraints);
        PresentationDefinition pd = new PresentationDefinition("test-presentation-definition", Arrays.asList(descriptor), null, null, null);
        return pd;
    }

    private List<DecryptedCredentialDTO> createMockWalletCredentials() throws JsonProcessingException {
        DecryptedCredentialDTO credential = new DecryptedCredentialDTO();
        credential.setId("test-credential-id");
        credential.setWalletId(walletId);

        VCCredentialProperties properties = new VCCredentialProperties();
        properties.setType(Arrays.asList("VerifiableCredential", "TestCredential"));
        VCCredentialResponse response = VCCredentialResponse.builder()
                .format("ldp_vc")
                .credential(properties)
                .build();

        credential.setCredential(response);

        CredentialMetadata metadata = new CredentialMetadata();
        metadata.setIssuerId("test-issuer-id");
        metadata.setCredentialType("TestCredential");
        credential.setCredentialMetadata(metadata);

        credential.setCreatedAt(Instant.now());
        credential.setUpdatedAt(Instant.now());

        return Arrays.asList(credential);
    }

    private VCCredentialResponse createMockVCCredentialResponse() {
        VCCredentialResponse response = new VCCredentialResponse();
        response.setFormat(CredentialFormat.LDP_VC.getFormat());

        Map<String, Object> credentialData = new HashMap<>();
        credentialData.put("type", Arrays.asList("VerifiableCredential", "TestCredential"));
        credentialData.put("credentialSubject", createMockCredentialSubject());

        response.setCredential(credentialData);
        return response;
    }

    private VCCredentialResponse createMockVCCredentialResponseWithSubject() {
        VCCredentialResponse response = createMockVCCredentialResponse();
        Map<String, Object> credentialData = (Map<String, Object>) response.getCredential();
        Map<String, Object> subject = new HashMap<>();
        subject.put("name", "John Doe");
        credentialData.put("credentialSubject", subject);
        return response;
    }

    private VCCredentialResponse createMockVCCredentialResponseWithDifferentFormat() {
        VCCredentialResponse response = new VCCredentialResponse();
        response.setFormat(CredentialFormat.VC_SD_JWT.getFormat());
        response.setCredential("jwt-token-here");
        return response;
    }

    private Map<String, Object> createMockCredentialSubject() {
        Map<String, Object> subject = new HashMap<>();
        subject.put("id", "did:example:123456789");
        subject.put("name", "Test Subject");
        return subject;
    }

    private Map<String, Object> createMockCredentialMap() {
        Map<String, Object> credentialMap = new HashMap<>();
        credentialMap.put("type", Arrays.asList("VerifiableCredential", "TestCredential"));
        credentialMap.put("credentialSubject", createMockCredentialSubject());
        return credentialMap;
    }

    private IssuerConfig createMockIssuerConfig() {
        IssuerDTO issuerDTO = new IssuerDTO();
        DisplayDTO display = new DisplayDTO();
        display.setName("Test Issuer");
        LogoDTO logoDTO = new LogoDTO();
        logoDTO.setUrl("dsds");
        display.setLogo(logoDTO);
        issuerDTO.setDisplay(Collections.singletonList(display));
        CredentialsSupportedResponse credentialsSupportedResponse = new CredentialsSupportedResponse();
        CredentialSupportedDisplayResponse  credentialSupportedDisplayResponse   = new CredentialSupportedDisplayResponse();
        credentialSupportedDisplayResponse.setName("test");
        credentialSupportedDisplayResponse.setLogo(logoDTO);
        credentialsSupportedResponse.setDisplay(Collections.singletonList(credentialSupportedDisplayResponse));
        IssuerConfig config = new IssuerConfig(issuerDTO, new CredentialIssuerWellKnownResponse(), credentialsSupportedResponse);
        return config;
    }
}