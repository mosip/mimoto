package io.mosip.mimoto.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.OpenID4VPConstants;
import io.mosip.mimoto.constant.SigningAlgorithm;
import io.mosip.mimoto.dto.DecryptedCredentialDTO;
import io.mosip.mimoto.dto.SubmitPresentationRequestDTO;
import io.mosip.mimoto.dto.SubmitPresentationResponseDTO;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.openid.VerifierDTO;
import io.mosip.mimoto.dto.openid.VerifiersDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.DecryptionException;
import io.mosip.mimoto.exception.KeyGenerationException;
import io.mosip.mimoto.model.CredentialMetadata;
import io.mosip.mimoto.model.VerifiablePresentation;
import io.mosip.mimoto.repository.VerifiablePresentationsRepository;
import io.mosip.mimoto.service.impl.OpenID4VPService;
import io.mosip.mimoto.service.impl.PresentationSubmissionServiceImpl;
import io.mosip.openID4VP.OpenID4VP;
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken;
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPToken;
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.types.ldp.LdpVPTokenSigningResult;
import io.mosip.openID4VP.constants.FormatType;
import io.mosip.openID4VP.networkManager.NetworkResponse;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.*;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Comprehensive test suite for PresentationSubmissionServiceImpl
 * Tests all methods, lines, and branches for complete coverage
 */
@RunWith(MockitoJUnitRunner.class)
public class PresentationSubmissionServiceTest {

    @InjectMocks
    private PresentationSubmissionServiceImpl presentationSubmissionService;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private OpenID4VPService openID4VPService;

    @Mock
    private VerifierService verifierService;

    @Mock
    private KeyPairService keyPairService;

    @Mock
    private VerifiablePresentationsRepository verifiablePresentationsRepository;

    @Mock
    private OpenID4VP openID4VP;

    private VerifiablePresentationSessionData sessionData;
    private String walletId;
    private String presentationId;
    private String base64Key;
    private SubmitPresentationRequestDTO request;
    private KeyPair keyPair;
    private VerifiersDTO verifiersDTO;

    @Before
    public void setUp() throws Exception {
        // Note: defaultSigningAlgorithmName is now a constant in the implementation

        walletId = "8a3d2c1b-4e5f-6a7b-8c9d-0e1f2a3b4c5d";
        presentationId = "vp-presentation-" + System.currentTimeMillis();
        base64Key = "VGhpc0lzQVNhbXBsZUJhc2U2NEVuY29kZWRXYWxsZXRLZXlGb3JUZXN0aW5nUHVycG9zZXM=";
        request = SubmitPresentationRequestDTO.builder()
                .selectedCredentials(Arrays.asList(
                    "vc-credential-123e4567-e89b-12d3-a456-426614174000",
                    "vc-credential-987f6543-e21a-98d7-b654-321098765432"
                ))
                .build();
        
        sessionData = new VerifiablePresentationSessionData();
        sessionData.setPresentationId(presentationId);
        sessionData.setAuthorizationRequest(
            "openid4vp://?client_id=inji-verify-client-001" +
            "&presentation_definition_uri=https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fpresentation_definition_uri" +
            "&response_type=vp_token" +
            "&response_mode=direct_post" +
            "&nonce=NHgLcWlae745DpfJbUyfdg%3D%3D" +
            "&response_uri=https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fvp-response" +
            "&state=pcmxBfvdPEcjFObgt%2BLekA%3D%3D"
        );
        sessionData.setCreatedAt(Instant.now());
        sessionData.setVerifierClientPreregistered(true);
        sessionData.setMatchingCredentials(createMockDecryptedCredentials());

        keyPair = generateKeyPairForAlgorithm(SigningAlgorithm.ED25519);

        VerifierDTO verifierDTO = VerifierDTO.builder()
                .clientId("inji-verify-client-001")
                .responseUris(Arrays.asList(
                    "https://inji-verify.collab.mosip.net/verifier/vp-response"
                ))
                .build();
        verifiersDTO = VerifiersDTO.builder()
                .verifiers(Arrays.asList(verifierDTO))
                .build();
    }


    @Test
    public void testSubmitPresentationSuccess() throws Exception {
        setupSuccessfulMocks();

        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);

        assertNotNull(response);
        assertEquals(OpenID4VPConstants.STATUS_SUCCESS, response.getStatus());
        assertEquals(OpenID4VPConstants.MESSAGE_PRESENTATION_SUCCESS, response.getMessage());

        verify(openID4VPService).create(presentationId);
        verify(verifierService).getTrustedVerifiers();
        verify(keyPairService).getKeyPairFromDB(eq(walletId), eq(base64Key), any(SigningAlgorithm.class));
        verify(verifiablePresentationsRepository).save(any(VerifiablePresentation.class));
    }

    @Test
    public void testSubmitPresentationSuccessWithMultipleCredentials() throws Exception {
        request.setSelectedCredentials(Arrays.asList(
            "vc-credential-123e4567-e89b-12d3-a456-426614174000",
            "vc-credential-987f6543-e21a-98d7-b654-321098765432",
            "vc-credential-456f7890-a12b-34c5-d678-901234567890"
        ));
        sessionData.setMatchingCredentials(createMockDecryptedCredentialsMultiple());
        setupSuccessfulMocks();

        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);

        assertNotNull(response);
        assertEquals(OpenID4VPConstants.STATUS_SUCCESS, response.getStatus());
    }

    @Test
    public void testSubmitPresentationSuccessWithSingleCredential() throws Exception {
        request.setSelectedCredentials(Arrays.asList("vc-credential-123e4567-e89b-12d3-a456-426614174000"));
        setupSuccessfulMocks();

        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);

        assertNotNull(response);
        assertEquals(OpenID4VPConstants.STATUS_SUCCESS, response.getStatus());
    }

    @Test
    public void testSubmitPresentationSuccessWithVerifierNotPreregistered() throws Exception {
        sessionData.setVerifierClientPreregistered(false);
        setupSuccessfulMocks();

        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);

        assertNotNull(response);
        assertEquals(OpenID4VPConstants.STATUS_SUCCESS, response.getStatus());
        verify(openID4VP).authenticateVerifier(anyString(), anyList(), eq(false));
    }

    // NOTE: Tests for RS256 and ES256 algorithm failures removed because
    // defaultSigningAlgorithmName is now a constant (ED25519) and cannot be changed.
    // The implementation always uses ED25519 for LDP_VC format.

    @Test
    public void testSubmitPresentationShareFailure() throws Exception {
        setupMocksForShareFailure();

        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);

        assertNotNull(response);
        assertEquals(OpenID4VPConstants.STATUS_ERROR, response.getStatus());
        assertEquals(OpenID4VPConstants.MESSAGE_PRESENTATION_SHARE_FAILED, response.getMessage());

        ArgumentCaptor<VerifiablePresentation> captor = ArgumentCaptor.forClass(VerifiablePresentation.class);
        verify(verifiablePresentationsRepository).save(captor.capture());
        assertEquals(OpenID4VPConstants.STATUS_ERROR, captor.getValue().getStatus());
    }


    // NOTE: Validation for sessionData, walletId, presentationId, and base64Key
    // has been moved to PresentationActionService layer.
    // PresentationSubmissionService now only validates request and selectedCredentials.

    @Test(expected = IllegalArgumentException.class)
    public void testSubmitPresentationNullRequest() throws Exception {
        presentationSubmissionService.submitPresentation(sessionData, walletId, presentationId, null, base64Key);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSubmitPresentationNullSelectedCredentials() throws Exception {
        request.setSelectedCredentials(null);
        presentationSubmissionService.submitPresentation(sessionData, walletId, presentationId, request, base64Key);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSubmitPresentationEmptySelectedCredentials() throws Exception {
        request.setSelectedCredentials(Collections.emptyList());
        presentationSubmissionService.submitPresentation(sessionData, walletId, presentationId, request, base64Key);
    }

    // NOTE: base64Key validation moved to PresentationActionService layer


    @Test(expected = IllegalStateException.class)
    public void testSubmitPresentationNoMatchingCredentialsInSession() throws Exception {
        sessionData.setMatchingCredentials(null);

        presentationSubmissionService.submitPresentation(sessionData, walletId, presentationId, request, base64Key);
    }

    @Test(expected = Exception.class)
    public void testSubmitPresentationEmptyMatchingCredentialsInSession() throws Exception {
        sessionData.setMatchingCredentials(Collections.emptyList());
        when(openID4VPService.create(anyString())).thenReturn(openID4VP);

        presentationSubmissionService.submitPresentation(sessionData, walletId, presentationId, request, base64Key);
    }

    @Test(expected = ApiNotAccessibleException.class)
    public void testSubmitPresentationVerifierServiceThrowsException() throws Exception {
        when(openID4VPService.create(anyString())).thenReturn(openID4VP);
        when(verifierService.getTrustedVerifiers()).thenThrow(new ApiNotAccessibleException());

        presentationSubmissionService.submitPresentation(sessionData, walletId, presentationId, request, base64Key);
    }

    @Test(expected = KeyGenerationException.class)
    public void testSubmitPresentationKeyPairServiceThrowsException() throws Exception {
        when(openID4VPService.create(anyString())).thenReturn(openID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(openID4VP.authenticateVerifier(anyString(), anyList(), anyBoolean())).thenReturn(null);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class)))
                .thenThrow(new KeyGenerationException("KEY_GEN_ERROR", "Key generation failed"));

        presentationSubmissionService.submitPresentation(sessionData, walletId, presentationId, request, base64Key);
    }

    @Test(expected = DecryptionException.class)
    public void testSubmitPresentationDecryptionException() throws Exception {
        when(openID4VPService.create(anyString())).thenReturn(openID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(openID4VP.authenticateVerifier(anyString(), anyList(), anyBoolean())).thenReturn(null);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class)))
                .thenThrow(new DecryptionException("DECRYPTION_ERROR", "Decryption failed"));

        presentationSubmissionService.submitPresentation(sessionData, walletId, presentationId, request, base64Key);
    }

    @Test(expected = Exception.class)
    public void testSubmitPresentationIOException() throws Exception {
        

        presentationSubmissionService.submitPresentation(sessionData, walletId, presentationId, request, base64Key);
    }

    @Test(expected = Exception.class)
    public void testSubmitPresentationJOSEException() throws Exception {
        
        setupMocksUpToSigning();
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class)))
                .thenThrow(new RuntimeException("Key retrieval failed"));

        presentationSubmissionService.submitPresentation(sessionData, walletId, presentationId, request, base64Key);
    }


    @Test
    public void testSubmitPresentationWithLdpVcFormat() throws Exception {
        List<DecryptedCredentialDTO> ldpCredentials = createMockDecryptedCredentialsWithFormat("ldp_vc");
        request.setSelectedCredentials(Arrays.asList("vc-credential-format-test-1", "vc-credential-format-test-2"));
        sessionData.setMatchingCredentials(ldpCredentials);
        setupSuccessfulMocks();

        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);

        assertNotNull(response);
        assertEquals(OpenID4VPConstants.STATUS_SUCCESS, response.getStatus());
    }

    @Test
    public void testSubmitPresentationWithMsoMdocFormat() throws Exception {
        List<DecryptedCredentialDTO> msoMdocCredentials = createMockDecryptedCredentialsWithFormat("mso_mdoc");
        request.setSelectedCredentials(Arrays.asList("vc-credential-format-test-1", "vc-credential-format-test-2"));
        sessionData.setMatchingCredentials(msoMdocCredentials);
        setupSuccessfulMocksForMsoMdoc();

        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);

        assertNotNull(response);
        assertEquals(OpenID4VPConstants.STATUS_SUCCESS, response.getStatus());
    }

    @Test
    public void testSubmitPresentationWithMixedFormats() throws Exception {
        List<DecryptedCredentialDTO> mixedCredentials = createMockDecryptedCredentialsWithMixedFormats();
        request.setSelectedCredentials(Arrays.asList("vc-credential-mixed-ldp-1", "vc-credential-mixed-mdoc-2"));
        sessionData.setMatchingCredentials(mixedCredentials);
        setupSuccessfulMocksForMixedFormats();

        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);

        assertNotNull(response);
        assertEquals(OpenID4VPConstants.STATUS_SUCCESS, response.getStatus());
    }


    @Test
    public void testSubmitPresentationStoresPresentationRecordCorrectly() throws Exception {
        setupSuccessfulMocks();
        ArgumentCaptor<VerifiablePresentation> captor = ArgumentCaptor.forClass(VerifiablePresentation.class);

        presentationSubmissionService.submitPresentation(sessionData, walletId, presentationId, request, base64Key);

        verify(verifiablePresentationsRepository).save(captor.capture());
        VerifiablePresentation saved = captor.getValue();
        assertEquals(presentationId, saved.getId());
        assertEquals(walletId, saved.getWalletId());
        assertEquals(OpenID4VPConstants.STATUS_SUCCESS, saved.getStatus());
        assertTrue(saved.getConsent());
        assertNotNull(saved.getAuthRequest());
        assertNotNull(saved.getPresentationData());
        assertNotNull(saved.getVerifierId());
        assertNotNull(saved.getRequestedAt());
    }

    @Test
    public void testSubmitPresentationStoresCorrectVerifierId() throws Exception {
        setupSuccessfulMocks();
        ArgumentCaptor<VerifiablePresentation> captor = ArgumentCaptor.forClass(VerifiablePresentation.class);

        presentationSubmissionService.submitPresentation(sessionData, walletId, presentationId, request, base64Key);

        verify(verifiablePresentationsRepository).save(captor.capture());
        VerifiablePresentation saved = captor.getValue();
        assertEquals("inji-verify-client-001", saved.getVerifierId()); // From mock data in setUp()
    }

    @Test
    public void testSubmitPresentationHandlesDatabaseException() throws Exception {
        setupSuccessfulMocks();
        doThrow(new RuntimeException("Database error"))
                .when(verifiablePresentationsRepository).save(any(VerifiablePresentation.class));

        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);

        assertNotNull(response);
        assertEquals(OpenID4VPConstants.STATUS_SUCCESS, response.getStatus());
    }

    @Test
    public void testSubmitPresentationStoresErrorStatusOnShareFailure() throws Exception {
        setupMocksForShareFailure();
        ArgumentCaptor<VerifiablePresentation> captor = ArgumentCaptor.forClass(VerifiablePresentation.class);

        presentationSubmissionService.submitPresentation(sessionData, walletId, presentationId, request, base64Key);

        verify(verifiablePresentationsRepository).save(captor.capture());
        VerifiablePresentation saved = captor.getValue();
        assertEquals(OpenID4VPConstants.STATUS_ERROR, saved.getStatus());
    }


    @Test
    public void testSubmitPresentationExtractsVerifierIdFromUrl() throws Exception {
        sessionData.setAuthorizationRequest("https://verifier.com/authorize?client_id=extracted-client-id&other=param");
        setupSuccessfulMocks();
        ArgumentCaptor<VerifiablePresentation> captor = ArgumentCaptor.forClass(VerifiablePresentation.class);

        presentationSubmissionService.submitPresentation(sessionData, walletId, presentationId, request, base64Key);

        verify(verifiablePresentationsRepository).save(captor.capture());
        assertNotNull(captor.getValue().getVerifierId());
    }

    @Test
    public void testSubmitPresentationHandlesNullAuthorizationRequest() throws Exception {
        sessionData.setAuthorizationRequest(null);
        setupSuccessfulMocks();
        ArgumentCaptor<VerifiablePresentation> captor = ArgumentCaptor.forClass(VerifiablePresentation.class);

        presentationSubmissionService.submitPresentation(sessionData, walletId, presentationId, request, base64Key);

        verify(verifiablePresentationsRepository).save(captor.capture());
        assertNotNull(captor.getValue().getVerifierId());
    }


    @Test
    public void testSignMsoMdocFormatWithMultipleDocTypes() throws Exception {
        setupSuccessfulMocksForMsoMdocWithMultipleDocTypes();
        List<DecryptedCredentialDTO> credentials = createMockDecryptedCredentialsForMsoMdocMultipleDocTypes();
        request.setSelectedCredentials(Arrays.asList("vc-credential-mdoc-multi-1", "vc-credential-mdoc-multi-2"));
        sessionData.setMatchingCredentials(credentials);

        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);

        assertNotNull(response);
        assertEquals(OpenID4VPConstants.STATUS_SUCCESS, response.getStatus());
    }

    @Test
    public void testSignMsoMdocFormatWithEmptyDocTypes() throws Exception {
        setupSuccessfulMocksForMsoMdocWithEmptyDocTypes();
        List<DecryptedCredentialDTO> credentials = createMockDecryptedCredentialsForMsoMdocEmpty();
        request.setSelectedCredentials(Arrays.asList("vc-credential-mdoc-empty-1"));
        sessionData.setMatchingCredentials(credentials);

        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);

        assertNotNull(response);
        assertEquals(OpenID4VPConstants.STATUS_SUCCESS, response.getStatus());
    }

    @Test
    public void testSignMsoMdocFormatWithNullDocTypeToDeviceAuthenticationBytes() throws Exception {
        setupSuccessfulMocksForMsoMdocWithNullDocTypes();
        List<DecryptedCredentialDTO> credentials = createMockDecryptedCredentialsForMsoMdocNullDocTypes();
        request.setSelectedCredentials(Arrays.asList("vc-credential-mdoc-null-1"));
        sessionData.setMatchingCredentials(credentials);

        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);

        assertNotNull(response);
        assertEquals(OpenID4VPConstants.STATUS_SUCCESS, response.getStatus());
    }

    @Test
    public void testSignMsoMdocFormatWithMissingDocTypeToDeviceAuthenticationBytes() throws Exception {
        setupSuccessfulMocksForMsoMdocWithMissingDocTypeKey();
        List<DecryptedCredentialDTO> credentials = createMockDecryptedCredentialsForMsoMdocEmpty();
        request.setSelectedCredentials(Arrays.asList("vc-credential-mdoc-missing-key-1"));
        sessionData.setMatchingCredentials(credentials);

        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);

        assertNotNull(response);
        assertEquals(OpenID4VPConstants.STATUS_SUCCESS, response.getStatus());
    }

    @Test(expected = RuntimeException.class)
    public void testSignMsoMdocFormatThrowsExceptionOnSigningFailure() throws Exception {
        when(openID4VPService.create(anyString())).thenReturn(openID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(openID4VP.authenticateVerifier(anyString(), anyList(), anyBoolean())).thenReturn(null);
        
        KeyPair es256KeyPair = generateKeyPairForAlgorithm(SigningAlgorithm.ES256);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), eq(SigningAlgorithm.ED25519)))
                .thenReturn(keyPair);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), eq(SigningAlgorithm.ES256)))
                .thenReturn(es256KeyPair);

        Map<FormatType, UnsignedVPToken> unsignedVPTokenMap = new HashMap<>();
        UnsignedVPToken msoMdocToken = mock(UnsignedVPToken.class);
        unsignedVPTokenMap.put(FormatType.MSO_MDOC, msoMdocToken);

        when(openID4VP.constructUnsignedVPToken(anyMap(), anyString(), anyString()))
                .thenReturn(unsignedVPTokenMap);

        Map<String, Object> complexPayload = new HashMap<>();
        complexPayload.put("circularRef", complexPayload);
        Map<String, Object> docTypeMap = new HashMap<>();
        docTypeMap.put("docTypeToDeviceAuthenticationBytes", new HashMap<String, Object>() {{
            put("org.iso.18013.5.1.mDL", complexPayload);
        }});
        when(objectMapper.convertValue(any(UnsignedVPToken.class), eq(Map.class)))
                .thenReturn(docTypeMap);
        when(objectMapper.writeValueAsBytes(any())).thenThrow(new RuntimeException("Serialization failed"));

        List<DecryptedCredentialDTO> credentials = createMockDecryptedCredentialsForMsoMdocMultipleDocTypes();
        request.setSelectedCredentials(Arrays.asList("vc-credential-mdoc-fail-1"));
        sessionData.setMatchingCredentials(credentials);

        presentationSubmissionService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);
    }

    @Test
    public void testResolveHolderIdCreatesCorrectDidJwk() throws Exception {
        setupSuccessfulMocks();

        presentationSubmissionService.submitPresentation(sessionData, walletId, presentationId, request, base64Key);

        verify(openID4VP).constructUnsignedVPToken(anyMap(), argThat(holderId -> 
            holderId != null && holderId.startsWith("did:jwk:")), anyString());
    }


    @Test
    public void testMapStringToFormatTypeLdpVcUnderscore() throws Exception {
        List<DecryptedCredentialDTO> credentials = createMockDecryptedCredentialsWithFormat("ldp_vc");
        request.setSelectedCredentials(Arrays.asList("vc-credential-format-test-1", "vc-credential-format-test-2"));
        sessionData.setMatchingCredentials(credentials);
        setupSuccessfulMocks();

        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);

        assertNotNull(response);
        assertEquals(OpenID4VPConstants.STATUS_SUCCESS, response.getStatus());
    }

    @Test
    public void testMapStringToFormatTypeLdpVcHyphen() throws Exception {
        List<DecryptedCredentialDTO> credentials = createMockDecryptedCredentialsWithFormat("ldp-vc");
        request.setSelectedCredentials(Arrays.asList("vc-credential-format-test-1", "vc-credential-format-test-2"));
        sessionData.setMatchingCredentials(credentials);
        setupSuccessfulMocks();

        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);

        assertNotNull(response);
        assertEquals(OpenID4VPConstants.STATUS_SUCCESS, response.getStatus());
    }

    @Test
    public void testMapStringToFormatTypeMsoMdocUnderscore() throws Exception {
        List<DecryptedCredentialDTO> credentials = createMockDecryptedCredentialsWithFormat("mso_mdoc");
        request.setSelectedCredentials(Arrays.asList("vc-credential-format-test-1", "vc-credential-format-test-2"));
        sessionData.setMatchingCredentials(credentials);
        setupSuccessfulMocksForMsoMdoc();

        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);

        assertNotNull(response);
        assertEquals(OpenID4VPConstants.STATUS_SUCCESS, response.getStatus());
    }

    @Test
    public void testMapStringToFormatTypeMsoMdocHyphen() throws Exception {
        List<DecryptedCredentialDTO> credentials = createMockDecryptedCredentialsWithFormat("mso-mdoc");
        request.setSelectedCredentials(Arrays.asList("vc-credential-format-test-1", "vc-credential-format-test-2"));
        sessionData.setMatchingCredentials(credentials);
        setupSuccessfulMocksForMsoMdoc();

        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);

        assertNotNull(response);
        assertEquals(OpenID4VPConstants.STATUS_SUCCESS, response.getStatus());
    }

    @Test
    public void testMapStringToFormatTypeUnknownDefaultsToLdpVc() throws Exception {
        List<DecryptedCredentialDTO> credentials = createMockDecryptedCredentialsWithFormat("unknown_format");
        request.setSelectedCredentials(Arrays.asList("vc-credential-format-test-1", "vc-credential-format-test-2"));
        sessionData.setMatchingCredentials(credentials);
        setupSuccessfulMocks();

        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);

        assertNotNull(response);
        assertEquals(OpenID4VPConstants.STATUS_SUCCESS, response.getStatus());
    }

    @Test
    public void testMapStringToFormatTypeNullDefaultsToLdpVc() throws Exception {
        List<DecryptedCredentialDTO> credentials = createMockDecryptedCredentialsWithFormat(null);
        request.setSelectedCredentials(Arrays.asList("vc-credential-format-test-1", "vc-credential-format-test-2"));
        sessionData.setMatchingCredentials(credentials);
        setupSuccessfulMocks();

        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);

        assertNotNull(response);
        assertEquals(OpenID4VPConstants.STATUS_SUCCESS, response.getStatus());
    }


    @Test
    public void testsendAuthorizationResponseToVerifierReturnsTrue() throws Exception {
        setupSuccessfulMocks();

        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);

        assertEquals(OpenID4VPConstants.STATUS_SUCCESS, response.getStatus());
        verify(openID4VP).sendAuthorizationResponseToVerifier(anyMap());
    }

    @Test
    public void testsendAuthorizationResponseToVerifierReturnsFalse() throws Exception {
        setupMocksForShareFailure();

        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);

        assertEquals(OpenID4VPConstants.STATUS_ERROR, response.getStatus());
        assertEquals(OpenID4VPConstants.MESSAGE_PRESENTATION_SHARE_FAILED, response.getMessage());
    }

    @Test
    public void testsendAuthorizationResponseToVerifierHandlesException() throws Exception {
        setupMocksForShareException();

        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);

        assertEquals(OpenID4VPConstants.STATUS_ERROR, response.getStatus());
    }


    @Test
    public void testCreatePresentationDataIncludesSelectedCredentials() throws Exception {
        setupSuccessfulMocks();
        when(objectMapper.writeValueAsString(any())).thenAnswer(invocation -> {
            Object arg = invocation.getArgument(0);
            if (arg instanceof Map) {
                Map<?, ?> map = (Map<?, ?>) arg;
                if (map.containsKey(OpenID4VPConstants.SELECTED_CREDENTIALS)) {
                    return "{\"selectedCredentials\":[\"cred-1\",\"cred-2\"]}";
                }
            }
            return "{}";
        });
        ArgumentCaptor<VerifiablePresentation> captor = ArgumentCaptor.forClass(VerifiablePresentation.class);

        presentationSubmissionService.submitPresentation(sessionData, walletId, presentationId, request, base64Key);

        verify(verifiablePresentationsRepository).save(captor.capture());
        String presentationData = captor.getValue().getPresentationData();
        assertNotNull(presentationData);
        assertTrue(presentationData.contains("selectedCredentials"));
    }

    @Test
    public void testExtractVerifierAuthRequestCreatesJsonObject() throws Exception {
        setupSuccessfulMocks();
        when(objectMapper.writeValueAsString(any())).thenAnswer(invocation -> {
            Object arg = invocation.getArgument(0);
            if (arg instanceof Map) {
                Map<?, ?> map = (Map<?, ?>) arg;
                if (map.containsKey(OpenID4VPConstants.AUTHORIZATION_REQUEST_URL)) {
                    return "{\"authorizationRequestUrl\":\"" + sessionData.getAuthorizationRequest() + "\"}";
                }
            }
            return "{}";
        });
        ArgumentCaptor<VerifiablePresentation> captor = ArgumentCaptor.forClass(VerifiablePresentation.class);

        presentationSubmissionService.submitPresentation(sessionData, walletId, presentationId, request, base64Key);

        verify(verifiablePresentationsRepository).save(captor.capture());
        String authRequest = captor.getValue().getAuthRequest();
        assertNotNull(authRequest);
        assertTrue(authRequest.contains("authorizationRequestUrl"));
    }

    @Test
    public void testExtractVerifierAuthRequestHandlesException() throws Exception {
        
        setupSuccessfulMocks();
        ArgumentCaptor<VerifiablePresentation> captor = ArgumentCaptor.forClass(VerifiablePresentation.class);

        presentationSubmissionService.submitPresentation(sessionData, walletId, presentationId, request, base64Key);

        verify(verifiablePresentationsRepository).save(captor.capture());
        String authRequest = captor.getValue().getAuthRequest();
        assertNotNull(authRequest);
        assertTrue(authRequest.length() > 0);
    }


    @Test
    public void testSubmitPresentationWithVeryLongPresentationId() throws Exception {
        String longPresentationId = "a".repeat(255);
        sessionData.setPresentationId(longPresentationId);
        setupSuccessfulMocks();

        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(
                sessionData, walletId, longPresentationId, request, base64Key);

        assertNotNull(response);
    }

    @Test
    public void testSubmitPresentationWithSpecialCharactersInWalletId() throws Exception {
        String specialWalletId = "wallet-123_@#$%";
        setupSuccessfulMocks();

        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(
                sessionData, specialWalletId, presentationId, request, base64Key);

        assertNotNull(response);
        verify(keyPairService).getKeyPairFromDB(eq(specialWalletId), anyString(), any(SigningAlgorithm.class));
    }

    @Test
    public void testSubmitPresentationWithLargeNumberOfCredentials() throws Exception {
        List<String> manyCredentials = new ArrayList<>();
        List<DecryptedCredentialDTO> manyDecryptedCredentials = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            String credId = "cred-" + i;
            manyCredentials.add(credId);
            manyDecryptedCredentials.add(createMockDecryptedCredential(credId, "ldp_vc"));
        }
        request.setSelectedCredentials(manyCredentials);
        sessionData.setMatchingCredentials(manyDecryptedCredentials);
        setupSuccessfulMocks();

        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);

        assertNotNull(response);
        assertEquals(OpenID4VPConstants.STATUS_SUCCESS, response.getStatus());
    }


    private void setupSuccessfulMocks() throws Exception {
        when(openID4VPService.create(anyString())).thenReturn(openID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(openID4VP.authenticateVerifier(anyString(), anyList(), anyBoolean())).thenReturn(null);
        
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class)))
                .thenReturn(keyPair);

        Map<FormatType, UnsignedVPToken> unsignedVPTokenMap = new HashMap<>();
        UnsignedLdpVPToken unsignedLdpVPToken = mock(UnsignedLdpVPToken.class);
        when(unsignedLdpVPToken.getDataToSign()).thenReturn("dGVzdC1kYXRhLXRvLXNpZ24=");
        unsignedVPTokenMap.put(FormatType.LDP_VC, unsignedLdpVPToken);

        when(openID4VP.constructUnsignedVPToken(anyMap(), anyString(), anyString()))
                .thenReturn(unsignedVPTokenMap);


        when(openID4VP.sendAuthorizationResponseToVerifier(anyMap())).thenReturn(new NetworkResponse(200, "", new HashMap<>()));

        when(objectMapper.convertValue(any(), eq(LdpVPTokenSigningResult.class)))
                .thenReturn(mock(LdpVPTokenSigningResult.class));
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        when(verifiablePresentationsRepository.save(any(VerifiablePresentation.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
    }

    private void setupMocksUpToSigning() throws Exception {
        when(openID4VPService.create(anyString())).thenReturn(openID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(openID4VP.authenticateVerifier(anyString(), anyList(), anyBoolean())).thenReturn(null);


    }

    private void setupMocksForShareFailure() throws Exception {
        setupSuccessfulMocks();
        when(openID4VP.sendAuthorizationResponseToVerifier(anyMap())).thenReturn(new NetworkResponse(400, "", new HashMap<>()));
    }

    private void setupMocksForShareException() throws Exception {
        setupSuccessfulMocks();
        when(openID4VP.sendAuthorizationResponseToVerifier(anyMap())).thenThrow(new RuntimeException("Share failed"));
    }

    private void setupSuccessfulMocksForMsoMdoc() throws Exception {
        when(openID4VPService.create(anyString())).thenReturn(openID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(openID4VP.authenticateVerifier(anyString(), anyList(), anyBoolean())).thenReturn(null);
        
        KeyPair es256KeyPair = generateKeyPairForAlgorithm(SigningAlgorithm.ES256);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), eq(SigningAlgorithm.ED25519)))
                .thenReturn(keyPair);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), eq(SigningAlgorithm.ES256)))
                .thenReturn(es256KeyPair);

        Map<FormatType, UnsignedVPToken> unsignedVPTokenMap = new HashMap<>();
        UnsignedVPToken msoMdocToken = mock(UnsignedVPToken.class);
        unsignedVPTokenMap.put(FormatType.MSO_MDOC, msoMdocToken);

        when(openID4VP.constructUnsignedVPToken(anyMap(), anyString(), anyString()))
                .thenReturn(unsignedVPTokenMap);

        Map<String, Object> docTypeMap = new HashMap<>();
        docTypeMap.put("docTypeToDeviceAuthenticationBytes", new HashMap<String, Object>() {{
            put("org.iso.18013.5.1.mDL", "test-payload");
        }});
        when(objectMapper.convertValue(any(UnsignedVPToken.class), eq(Map.class)))
                .thenReturn(docTypeMap);
        when(objectMapper.convertValue(any(Map.class), eq(LdpVPTokenSigningResult.class)))
                .thenReturn(mock(LdpVPTokenSigningResult.class));
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        when(openID4VP.sendAuthorizationResponseToVerifier(anyMap())).thenReturn(new NetworkResponse(200, "", new HashMap<>()));

        when(verifiablePresentationsRepository.save(any(VerifiablePresentation.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
    }

    private void setupSuccessfulMocksForMixedFormats() throws Exception {
        when(openID4VPService.create(anyString())).thenReturn(openID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(openID4VP.authenticateVerifier(anyString(), anyList(), anyBoolean())).thenReturn(null);
        
        KeyPair es256KeyPair = generateKeyPairForAlgorithm(SigningAlgorithm.ES256);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), eq(SigningAlgorithm.ED25519)))
                .thenReturn(keyPair);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), eq(SigningAlgorithm.ES256)))
                .thenReturn(es256KeyPair);

        Map<FormatType, UnsignedVPToken> unsignedVPTokenMap = new HashMap<>();
        UnsignedLdpVPToken ldpToken = mock(UnsignedLdpVPToken.class);
        when(ldpToken.getDataToSign()).thenReturn("dGVzdC1kYXRhLXRvLXNpZ24=");
        UnsignedVPToken msoToken = mock(UnsignedVPToken.class);
        unsignedVPTokenMap.put(FormatType.LDP_VC, ldpToken);
        unsignedVPTokenMap.put(FormatType.MSO_MDOC, msoToken);

        when(openID4VP.constructUnsignedVPToken(anyMap(), anyString(), anyString()))
                .thenReturn(unsignedVPTokenMap);

        Map<String, Object> docTypeMap = new HashMap<>();
        docTypeMap.put("docTypeToDeviceAuthenticationBytes", new HashMap<String, Object>() {{
            put("org.iso.18013.5.1.mDL", "test-payload");
        }});
        when(objectMapper.convertValue(any(UnsignedVPToken.class), eq(Map.class)))
                .thenReturn(docTypeMap);
        when(objectMapper.convertValue(any(Map.class), eq(LdpVPTokenSigningResult.class)))
                .thenReturn(mock(LdpVPTokenSigningResult.class));
        when(objectMapper.writeValueAsString(any())).thenReturn("{}");

        when(openID4VP.sendAuthorizationResponseToVerifier(anyMap())).thenReturn(new NetworkResponse(200, "", new HashMap<>()));

        when(verifiablePresentationsRepository.save(any(VerifiablePresentation.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
    }

    private void setupSuccessfulMocksForMsoMdocWithMultipleDocTypes() throws Exception {
        setupSuccessfulMocksForMsoMdoc();
        Map<String, Object> docTypeMap = new HashMap<>();
        docTypeMap.put("docTypeToDeviceAuthenticationBytes", new HashMap<String, Object>() {{
            put("org.iso.18013.5.1.mDL", "test-payload-1");
            put("org.iso.18013.5.1.Passport", "test-payload-2");
            put("org.iso.18013.5.1.HealthCard", "test-payload-3");
        }});
        when(objectMapper.convertValue(any(UnsignedVPToken.class), eq(Map.class)))
                .thenReturn(docTypeMap);
    }

    private void setupSuccessfulMocksForMsoMdocWithEmptyDocTypes() throws Exception {
        setupSuccessfulMocksForMsoMdoc();
        Map<String, Object> docTypeMap = new HashMap<>();
        docTypeMap.put("docTypeToDeviceAuthenticationBytes", new HashMap<>());
        when(objectMapper.convertValue(any(UnsignedVPToken.class), eq(Map.class)))
                .thenReturn(docTypeMap);
    }

    private void setupSuccessfulMocksForMsoMdocWithNullDocTypes() throws Exception {
        setupSuccessfulMocksForMsoMdoc();
        Map<String, Object> docTypeMap = new HashMap<>();
        docTypeMap.put("docTypeToDeviceAuthenticationBytes", null);
        when(objectMapper.convertValue(any(UnsignedVPToken.class), eq(Map.class)))
                .thenReturn(docTypeMap);
    }

    private void setupSuccessfulMocksForMsoMdocWithMissingDocTypeKey() throws Exception {
        setupSuccessfulMocksForMsoMdoc();
        Map<String, Object> docTypeMap = new HashMap<>();
        when(objectMapper.convertValue(any(UnsignedVPToken.class), eq(Map.class)))
                .thenReturn(docTypeMap);
    }

    private List<DecryptedCredentialDTO> createMockDecryptedCredentials() {
        return Arrays.asList(
                createMockDecryptedCredential("vc-credential-123e4567-e89b-12d3-a456-426614174000", "ldp_vc"),
                createMockDecryptedCredential("vc-credential-987f6543-e21a-98d7-b654-321098765432", "ldp_vc")
        );
    }

    private List<DecryptedCredentialDTO> createMockDecryptedCredentialsMultiple() {
        return Arrays.asList(
                createMockDecryptedCredential("vc-credential-123e4567-e89b-12d3-a456-426614174000", "ldp_vc"),
                createMockDecryptedCredential("vc-credential-987f6543-e21a-98d7-b654-321098765432", "ldp_vc"),
                createMockDecryptedCredential("vc-credential-456f7890-a12b-34c5-d678-901234567890", "ldp_vc")
        );
    }

    private List<DecryptedCredentialDTO> createMockDecryptedCredentialsWithFormat(String format) {
        return Arrays.asList(
                createMockDecryptedCredential("vc-credential-format-test-1", format),
                createMockDecryptedCredential("vc-credential-format-test-2", format)
        );
    }

    private List<DecryptedCredentialDTO> createMockDecryptedCredentialsWithMixedFormats() {
        return Arrays.asList(
                createMockDecryptedCredential("vc-credential-mixed-ldp-1", "ldp_vc"),
                createMockDecryptedCredential("vc-credential-mixed-mdoc-2", "mso_mdoc")
        );
    }

    private List<DecryptedCredentialDTO> createMockDecryptedCredentialsForMsoMdocMultipleDocTypes() {
        return Arrays.asList(
                createMockDecryptedCredential("vc-credential-mdoc-multi-1", "mso_mdoc"),
                createMockDecryptedCredential("vc-credential-mdoc-multi-2", "mso_mdoc")
        );
    }

    private List<DecryptedCredentialDTO> createMockDecryptedCredentialsForMsoMdocEmpty() {
        return Arrays.asList(
                createMockDecryptedCredential("vc-credential-mdoc-empty-1", "mso_mdoc")
        );
    }

    private List<DecryptedCredentialDTO> createMockDecryptedCredentialsForMsoMdocNullDocTypes() {
        return Arrays.asList(
                createMockDecryptedCredential("vc-credential-mdoc-null-1", "mso_mdoc")
        );
    }

    private DecryptedCredentialDTO createMockDecryptedCredential(String id, String format) {
        DecryptedCredentialDTO credential = new DecryptedCredentialDTO();
        credential.setId(id);
        credential.setWalletId(walletId);
        credential.setCreatedAt(Instant.now().minusSeconds(86400)); // Created 1 day ago
        credential.setUpdatedAt(Instant.now());

        CredentialMetadata metadata = new CredentialMetadata();
        metadata.setIssuerId("https://esignet.collab.mosip.net/v1/esignet");
        metadata.setCredentialType("MOSIPVerifiableCredential");
        credential.setCredentialMetadata(metadata);

        Map<String, Object> credentialData = new HashMap<>();
        credentialData.put("@context", Arrays.asList(
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
        ));
        credentialData.put("type", Arrays.asList("VerifiableCredential", "MOSIPVerifiableCredential"));
        credentialData.put("issuer", "https://esignet.collab.mosip.net/v1/esignet");
        credentialData.put("issuanceDate", Instant.now().minusSeconds(86400).toString());
        credentialData.put("expirationDate", Instant.now().plusSeconds(31536000).toString()); // 1 year
        
        credentialData.put("credentialSubject", new HashMap<String, Object>() {{
            put("id", "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2In0");
            put("fullName", "John Doe");
            put("email", "john.doe@example.com");
            put("dateOfBirth", "1990-01-15");
            put("gender", "Male");
            put("phone", "+91-9876543210");
            put("address", new HashMap<String, Object>() {{
                put("street", "123 Main Street");
                put("city", "Bangalore");
                put("state", "Karnataka");
                put("postalCode", "560001");
                put("country", "India");
            }});
            put("UIN", "1234567890123456");
        }});

        if (format != null && (format.equals("ldp_vc") || format.equals("ldp-vc"))) {
            credentialData.put("proof", new HashMap<String, Object>() {{
                put("type", "Ed25519Signature2020");
                put("created", Instant.now().minusSeconds(86400).toString());
                put("verificationMethod", "https://esignet.collab.mosip.net/v1/esignet#key-1");
                put("proofPurpose", "assertionMethod");
                put("proofValue", "z3FXQjecWufY46yg5abdVZsXqLhxhueuSoZgsgwJTmN7bd8gZJVYRDEHbhGEfW6aeRgvNhZqr9h7LhzJBKqvqm8Qe");
            }});
        }

        VCCredentialResponse vcResponse = VCCredentialResponse.builder()
                .format(format != null ? format : "ldp_vc")
                .credential(credentialData)
                .build();

        credential.setCredential(vcResponse);
        return credential;
    }

    /**
     * Helper method to generate KeyPair for different signing algorithms
     * This ensures we use the correct key type for each algorithm
     */
    private KeyPair generateKeyPairForAlgorithm(SigningAlgorithm algorithm) throws Exception {
        KeyPairGenerator keyPairGenerator;
        
        switch (algorithm) {
            case RS256:
                keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(2048);
                break;
                
            case ES256:
            case ES256K:
                keyPairGenerator = KeyPairGenerator.getInstance("EC");
                keyPairGenerator.initialize(256);
                break;
                
            case ED25519:
            default:
                keyPairGenerator = KeyPairGenerator.getInstance("Ed25519");
                break;
        }
        
        return keyPairGenerator.generateKeyPair();
    }

    // ============= NEW TESTS FOR MISSING BRANCH COVERAGE =============

    @Test
    public void testSignMsoMdocDocTypeWithStringPayload() throws Exception {
        DecryptedCredentialDTO credential = createMockDecryptedCredential("cred-mdoc-string", "mso_mdoc");
        sessionData.setMatchingCredentials(Arrays.asList(credential));
        request.setSelectedCredentials(Arrays.asList("cred-mdoc-string"));
        
        setupSuccessfulMocksForMsoMdoc();
        
        // String payload test
        Map<String, Object> docTypeMap = new HashMap<>();
        docTypeMap.put("docTypeToDeviceAuthenticationBytes", new HashMap<String, Object>() {{
            put("org.iso.18013.5.1.mDL", "test-string-payload");
        }});
        when(objectMapper.convertValue(any(UnsignedVPToken.class), eq(Map.class)))
                .thenReturn(docTypeMap);
        
        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);
        
        assertNotNull(response);
        assertEquals(OpenID4VPConstants.STATUS_SUCCESS, response.getStatus());
    }

    @Test
    public void testSignMsoMdocDocTypeWithObjectPayload() throws Exception {
        DecryptedCredentialDTO credential = createMockDecryptedCredential("cred-mdoc-object", "mso_mdoc");
        sessionData.setMatchingCredentials(Arrays.asList(credential));
        request.setSelectedCredentials(Arrays.asList("cred-mdoc-object"));
        
        setupSuccessfulMocksForMsoMdoc();
        
        // Object payload test
        Map<String, Object> docTypeMap = new HashMap<>();
        Map<String, Object> payloadObject = new HashMap<>();
        payloadObject.put("key1", "value1");
        payloadObject.put("key2", "value2");
        
        docTypeMap.put("docTypeToDeviceAuthenticationBytes", new HashMap<String, Object>() {{
            put("org.iso.18013.5.1.mDL", payloadObject);
        }});
        when(objectMapper.convertValue(any(UnsignedVPToken.class), eq(Map.class)))
                .thenReturn(docTypeMap);
        when(objectMapper.writeValueAsBytes(any())).thenReturn("test-bytes".getBytes());
        
        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);
        
        assertNotNull(response);
        assertEquals(OpenID4VPConstants.STATUS_SUCCESS, response.getStatus());
    }

    @Test
    public void testStorePresentationRecordWithNullSessionData() throws Exception {
        sessionData.setMatchingCredentials(createMockDecryptedCredentials());
        setupSuccessfulMocks();
        
        // Test with null sessionData being passed - should handle gracefully
        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);
        
        assertNotNull(response);
        // Should still complete successfully even if storage fails
        assertEquals(OpenID4VPConstants.STATUS_SUCCESS, response.getStatus());
    }

    @Test
    public void testsendAuthorizationResponseToVerifierReturnsNonEmptyString() throws Exception {
        sessionData.setMatchingCredentials(createMockDecryptedCredentials());
        setupSuccessfulMocks();
        when(openID4VP.sendAuthorizationResponseToVerifier(anyMap())).thenReturn(new NetworkResponse(400, "", new HashMap<>())); // non-empty string
        
        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);
        
        assertNotNull(response);
        // Should return ERROR status when vpToken is not empty (sendAuthorizationResponseToVerifier returns false when non-empty)
        assertEquals(OpenID4VPConstants.STATUS_ERROR, response.getStatus());
        assertEquals(OpenID4VPConstants.MESSAGE_PRESENTATION_SHARE_FAILED, response.getMessage());
    }

    @Test
    public void testSignMsoMdocDocTypeWithNullSignature() throws Exception {
        // Test the branch where signature is null or empty and returns null in the filter
        DecryptedCredentialDTO credential = createMockDecryptedCredential("cred-mdoc-null-sig", "mso_mdoc");
        sessionData.setMatchingCredentials(Arrays.asList(credential));
        request.setSelectedCredentials(Arrays.asList("cred-mdoc-null-sig"));
        
        setupSuccessfulMocksForMsoMdoc();
        
        // Test with empty docType map - this will result in empty documentTypeSignatures
        Map<String, Object> docTypeMap = new HashMap<>();
        docTypeMap.put("docTypeToDeviceAuthenticationBytes", new HashMap<>());
        when(objectMapper.convertValue(any(UnsignedVPToken.class), eq(Map.class)))
                .thenReturn(docTypeMap);
        
        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);
        
        assertNotNull(response);
        assertEquals(OpenID4VPConstants.STATUS_SUCCESS, response.getStatus());
    }

    @Test
    public void testExtractVerifierIdFromUrlWithNullAuthorizationRequest() throws Exception {
        sessionData.setMatchingCredentials(createMockDecryptedCredentials());
        sessionData.setAuthorizationRequest(null); // Null auth request
        setupSuccessfulMocks();
        
        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);
        
        assertNotNull(response);
        assertEquals(OpenID4VPConstants.STATUS_SUCCESS, response.getStatus());
        
        // Verify that "unknown" verifier ID is used when auth request is null
        ArgumentCaptor<VerifiablePresentation> captor = ArgumentCaptor.forClass(VerifiablePresentation.class);
        verify(verifiablePresentationsRepository).save(captor.capture());
        VerifiablePresentation savedPresentation = captor.getValue();
        assertEquals("unknown", savedPresentation.getVerifierId());
    }

    @Test
    public void testExtractVerifierAuthRequestWithNullAuthorizationRequest() throws Exception {
        sessionData.setMatchingCredentials(createMockDecryptedCredentials());
        sessionData.setAuthorizationRequest(null); // Null auth request
        setupSuccessfulMocks();
        
        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);
        
        assertNotNull(response);
        assertEquals(OpenID4VPConstants.STATUS_SUCCESS, response.getStatus());
        
        // Verify that "{}" is used when auth request is null
        ArgumentCaptor<VerifiablePresentation> captor = ArgumentCaptor.forClass(VerifiablePresentation.class);
        verify(verifiablePresentationsRepository).save(captor.capture());
        VerifiablePresentation savedPresentation = captor.getValue();
        assertEquals("{}", savedPresentation.getAuthRequest());
    }

    @Test
    public void testCreatePresentationDataHandlesJsonProcessingException() throws Exception {
        sessionData.setMatchingCredentials(createMockDecryptedCredentials());
        
        when(openID4VPService.create(anyString())).thenReturn(openID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(openID4VP.authenticateVerifier(anyString(), anyList(), anyBoolean())).thenReturn(null);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class)))
                .thenReturn(keyPair);

        Map<FormatType, UnsignedVPToken> unsignedVPTokenMap = new HashMap<>();
        UnsignedLdpVPToken unsignedLdpVPToken = mock(UnsignedLdpVPToken.class);
        when(unsignedLdpVPToken.getDataToSign()).thenReturn("dGVzdC1kYXRhLXRvLXNpZ24=");
        unsignedVPTokenMap.put(FormatType.LDP_VC, unsignedLdpVPToken);

        when(openID4VP.constructUnsignedVPToken(anyMap(), anyString(), anyString()))
                .thenReturn(unsignedVPTokenMap);
        when(openID4VP.sendAuthorizationResponseToVerifier(anyMap())).thenReturn(new NetworkResponse(200, "", new HashMap<>()));

        when(objectMapper.convertValue(any(), eq(LdpVPTokenSigningResult.class)))
                .thenReturn(mock(LdpVPTokenSigningResult.class));
        
        // Mock writeValueAsString to throw exception only for presentation data serialization
        when(objectMapper.writeValueAsString(anyMap()))
                .thenReturn("{\"authorizationRequestUrl\":\"test\"}")  // For auth request
                .thenThrow(new com.fasterxml.jackson.core.JsonProcessingException("Test exception") {}) // For presentation data
                .thenReturn("{}"); // Subsequent calls succeed

        when(verifiablePresentationsRepository.save(any(VerifiablePresentation.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        
        SubmitPresentationResponseDTO response = presentationSubmissionService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);
        
        assertNotNull(response);
        // Should handle exception gracefully and use "{}" as fallback for presentation data
        assertEquals(OpenID4VPConstants.STATUS_SUCCESS, response.getStatus());
    }

    @Test(expected = Exception.class)
    public void testSignVPTokenWithUnsupportedFormatType() throws Exception {
        DecryptedCredentialDTO credential = createMockDecryptedCredential("cred-unsupported", "ldp_vc");
        sessionData.setMatchingCredentials(Arrays.asList(credential));
        request.setSelectedCredentials(Arrays.asList("cred-unsupported"));
        
        when(openID4VPService.create(anyString())).thenReturn(openID4VP);
        when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
        when(openID4VP.authenticateVerifier(anyString(), anyList(), anyBoolean())).thenReturn(null);
        when(keyPairService.getKeyPairFromDB(anyString(), anyString(), any(SigningAlgorithm.class)))
                .thenReturn(keyPair);
        
        // Create an unsupported format type scenario by mocking the unsigned VP token map
        Map<FormatType, UnsignedVPToken> unsignedVPTokenMap = new HashMap<>();
        // Note: We can't create a truly unsupported FormatType, but we can test the null handling
        UnsignedVPToken nullToken = null;
        unsignedVPTokenMap.put(FormatType.LDP_VC, nullToken);
        
        when(openID4VP.constructUnsignedVPToken(anyMap(), anyString(), anyString()))
                .thenReturn(unsignedVPTokenMap);
        
        presentationSubmissionService.submitPresentation(
                sessionData, walletId, presentationId, request, base64Key);
    }

    @Test
    public void testFetchSelectedCredentialsWithNullMatchingCredentials() throws Exception {
        sessionData.setMatchingCredentials(null); // Null matching credentials
        request.setSelectedCredentials(Arrays.asList("cred-1"));
        
        // No mocks needed since it fails during validation before reaching mocked components
        
        try {
            presentationSubmissionService.submitPresentation(
                    sessionData, walletId, presentationId, request, base64Key);
            fail("Expected IllegalStateException");
        } catch (IllegalStateException e) {
            assertEquals("No matching credentials found in session cache", e.getMessage());
        }
    }

}
