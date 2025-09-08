package io.mosip.mimoto.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.dto.VerifiablePresentationResponseDTO;
import io.mosip.mimoto.dto.mimoto.VCCredentialProperties;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponseProof;
import io.mosip.mimoto.dto.openid.VerifierDTO;
import io.mosip.mimoto.dto.openid.VerifiersDTO;
import io.mosip.mimoto.dto.openid.presentation.InputDescriptorDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationDefinitionDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationRequestDTO;
import io.mosip.mimoto.exception.VPNotCreatedException;
import io.mosip.mimoto.service.impl.DataShareServiceImpl;
import io.mosip.mimoto.service.impl.OpenID4VPFactory;
import io.mosip.mimoto.service.impl.PresentationServiceImpl;
import io.mosip.mimoto.util.JwtUtils;
import io.mosip.mimoto.util.TestUtilities;
import io.mosip.openID4VP.OpenID4VP;
import io.mosip.openID4VP.authorizationRequest.Verifier;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.time.Instant;
import java.util.*;

import static io.mosip.mimoto.util.JwtUtils.parseJwtHeader;
import static org.junit.Assert.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static io.mosip.mimoto.util.TestUtilities.*;

@RunWith(MockitoJUnitRunner.class)
public class PresentationServiceTest {
    @Mock
    VerifierService verifierService;
    @Mock
    DataShareServiceImpl dataShareService;
    @Mock
    ObjectMapper objectMapper;

    @Mock
    private OpenID4VPFactory openID4VPFactory;

    @InjectMocks
    PresentationServiceImpl presentationService;

    String walletId, clientId, urlEncodedVPAuthorizationRequest;
    VerifiersDTO verifiersDTO;
    VerifierDTO verifierDTO;
    List<Verifier> preRegisteredVerifiers;
    UUID fixedUuid;
    Instant fixedInstant;

    @Before
    public void setup() throws JsonProcessingException {
        ReflectionTestUtils.setField(presentationService, "injiOvpRedirectURLPattern", "%s#vp_token=%s&presentation_submission=%s");
        ReflectionTestUtils.setField(presentationService, "maximumResponseHeaderSize", 65536);
        when(objectMapper.writeValueAsString(any())).thenReturn("test-data");

        // Setup for Wallet presentation tests
        walletId = "wallet-123";
        clientId = "test-clientId";
        urlEncodedVPAuthorizationRequest =
                "client_id=test-clientId&presentation_definition_uri=https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fpresentation_definition_uri&response_type=vp_token&response_mode=direct_post&nonce=NHgLcWlae745DpfJbUyfdg%253D%253D&response_uri=https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fvp-response&state=pcmxBfvdPEcjFObgt%252BLekA%253D%253D";

        verifierDTO = new VerifierDTO(
                clientId,
                List.of("redirect-uri"),
                List.of("https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fvp-response"),
                null
        );
        verifiersDTO = new VerifiersDTO();
        verifiersDTO.setVerifiers(List.of(verifierDTO));
        preRegisteredVerifiers = List.of(
                new Verifier(verifierDTO.getClientId(), verifierDTO.getResponseUris())
        );

        fixedUuid = UUID.fromString("123e4567-e89b-12d3-a456-426614174000");
        fixedInstant = Instant.parse("2025-09-08T12:34:56Z");
    }

    @Test
    public void credentialProofMatchingWithVPRequest() throws Exception {
        VCCredentialResponse vcCredentialResponse = TestUtilities.getVCCredentialResponseDTO("Ed25519Signature2020");
        PresentationRequestDTO presentationRequestDTO = TestUtilities.getPresentationRequestDTO();

        when(dataShareService.downloadCredentialFromDataShare(eq(presentationRequestDTO))).thenReturn(vcCredentialResponse);
        when(objectMapper.convertValue(eq(vcCredentialResponse.getCredential()), eq(VCCredentialProperties.class)))
                .thenReturn((VCCredentialProperties) vcCredentialResponse.getCredential());
        String expectedRedirectUrl = "test_redirect_uri#vp_token=dGVzdC1kYXRh&presentation_submission=test-data";

        String actualRedirectUrl = presentationService.authorizePresentation(TestUtilities.getPresentationRequestDTO());

        assertEquals(expectedRedirectUrl, actualRedirectUrl);
    }

    @Test(expected = VPNotCreatedException.class)
    public void credentialProofMismatchWithVPRequest() throws IOException {
        VCCredentialResponse vcCredentialResponse = TestUtilities.getVCCredentialResponseDTO("RSASignature2020");
        PresentationRequestDTO presentationRequestDTO = TestUtilities.getPresentationRequestDTO();
        when(dataShareService.downloadCredentialFromDataShare(eq(presentationRequestDTO))).thenReturn(vcCredentialResponse);
        when(objectMapper.convertValue(eq(vcCredentialResponse.getCredential()), eq(VCCredentialProperties.class)))
                .thenReturn((VCCredentialProperties) vcCredentialResponse.getCredential());
        presentationService.authorizePresentation(TestUtilities.getPresentationRequestDTO());
    }

    @Test
    public void sdJwtCredentialMatchingWithVPRequest() throws Exception {
        VCCredentialResponse vcCredentialResponse = createSDJwtCredentialResponse("vc+sd-jwt");
        PresentationRequestDTO presentationRequestDTO = createSDJwtPresentationRequest();
        Map<String, Object> jwtHeaders = Map.of("alg", "ES256", "typ", "JWT");

        when(dataShareService.downloadCredentialFromDataShare(eq(presentationRequestDTO))).thenReturn(vcCredentialResponse);
        when(objectMapper.convertValue(eq(vcCredentialResponse.getCredential()), eq(String.class)))
                .thenReturn("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.test.signature");

        try (MockedStatic<io.mosip.mimoto.util.JwtUtils> jwtUtilsMock = mockStatic(io.mosip.mimoto.util.JwtUtils.class)) {
            jwtUtilsMock.when(() -> parseJwtHeader(anyString())).thenReturn(jwtHeaders);

            String expectedRedirectUrl = "test_redirect_uri#vp_token=dGVzdC1kYXRh&presentation_submission=test-data";
            String actualRedirectUrl = presentationService.authorizePresentation(presentationRequestDTO);

            assertEquals(expectedRedirectUrl, actualRedirectUrl);
        }
    }

    // Error handling - essential for robustness
    @Test(expected = VPNotCreatedException.class)
    public void nullPresentationDefinitionWithVPRequest() throws IOException {
        VCCredentialResponse vcCredentialResponse = TestUtilities.getVCCredentialResponseDTO("Ed25519Signature2020");
        PresentationRequestDTO presentationRequestDTO = TestUtilities.getPresentationRequestDTO();
        presentationRequestDTO.setPresentationDefinition(null);

        when(dataShareService.downloadCredentialFromDataShare(eq(presentationRequestDTO))).thenReturn(vcCredentialResponse);

        presentationService.authorizePresentation(presentationRequestDTO);
    }

    @Test(expected = VPNotCreatedException.class)
    public void uriTooLongWithVPRequest() throws IOException {
        ReflectionTestUtils.setField(presentationService, "maximumResponseHeaderSize", 10); // Very small limit

        VCCredentialResponse vcCredentialResponse = TestUtilities.getVCCredentialResponseDTO("Ed25519Signature2020");
        PresentationRequestDTO presentationRequestDTO = TestUtilities.getPresentationRequestDTO();

        when(dataShareService.downloadCredentialFromDataShare(eq(presentationRequestDTO))).thenReturn(vcCredentialResponse);
        when(objectMapper.convertValue(eq(vcCredentialResponse.getCredential()), eq(VCCredentialProperties.class)))
                .thenReturn((VCCredentialProperties) vcCredentialResponse.getCredential());
        when(objectMapper.writeValueAsString(any())).thenReturn("very-long-test-data-that-exceeds-limit");

        presentationService.authorizePresentation(presentationRequestDTO);
    }

    // Presentation definition construction - key functionality
    @Test
    public void constructPresentationDefinitionForLdpVcCredential() {
        VCCredentialResponse vcCredentialResponse = createLdpVcCredentialResponse();
        VCCredentialProperties credential = (VCCredentialProperties) vcCredentialResponse.getCredential();
        when(objectMapper.convertValue(eq(vcCredentialResponse.getCredential()), eq(VCCredentialProperties.class)))
                .thenReturn(credential);

        PresentationDefinitionDTO result = presentationService.constructPresentationDefinition(vcCredentialResponse);

        assertNotNull(result);
        assertNotNull(result.getId());
        assertEquals(1, result.getInputDescriptors().size());

        InputDescriptorDTO inputDescriptor = result.getInputDescriptors().get(0);
        assertNotNull(inputDescriptor.getId());
        assertTrue(inputDescriptor.getFormat().containsKey("ldpVc"));
        assertTrue(inputDescriptor.getFormat().get("ldpVc").containsKey("proofTypes"));
    }

    @Test
    public void constructPresentationDefinitionForSdJwtCredential() {
        VCCredentialResponse vcCredentialResponse = createSDJwtCredentialResponse("vc+sd-jwt");
        Map<String, Object> jwtPayload = Map.of("type", Arrays.asList("VerifiableCredential", "TestCredential"));
        Map<String, Object> jwtHeaders = Map.of("alg", "ES256", "typ", "JWT");

        try (MockedStatic<JwtUtils> jwtUtilsMock = mockStatic(io.mosip.mimoto.util.JwtUtils.class)) {
            jwtUtilsMock.when(() -> JwtUtils.extractJwtPayloadFromSdJwt(anyString())).thenReturn(jwtPayload);
            jwtUtilsMock.when(() -> JwtUtils.parseJwtHeader(anyString())).thenReturn(jwtHeaders);

            PresentationDefinitionDTO result = presentationService.constructPresentationDefinition(vcCredentialResponse);

            assertNotNull(result);
            assertEquals(1, result.getInputDescriptors().size());
            assertTrue(result.getInputDescriptors().get(0).getFormat().containsKey("vc+sd-jwt"));
        }
    }

    @Test
    public void testHandleVPAuthorizationRequest_successful() throws Exception {
        try (MockedStatic<UUID> mockedStatic = mockStatic(UUID.class);
             MockedStatic<Instant> mockedInstant = mockStatic(Instant.class)) {

            mockedStatic.when(UUID::randomUUID).thenReturn(fixedUuid);
            mockedInstant.when(Instant::now).thenReturn(fixedInstant);

            when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
            when(verifierService.isVerifierTrustedByWallet(clientId, walletId)).thenReturn(true);

            OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
            when(openID4VPFactory.create(anyString())).thenReturn(mockOpenID4VP);
            when(mockOpenID4VP.authenticateVerifier(urlEncodedVPAuthorizationRequest, preRegisteredVerifiers))
                    .thenReturn(getPresentationAuthorizationRequest(clientId, "https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fvp-response"));

            VerifiablePresentationResponseDTO expectedPresentationResponseDTO = getVerifiablePresentationResponseDTO("test-clientId", "test-clientId", null, true, true, "https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fvp-response", mockOpenID4VP, fixedInstant);

            VerifiablePresentationResponseDTO actualPresentationResponseDTO =
                    presentationService.handleVPAuthorizationRequest(urlEncodedVPAuthorizationRequest, walletId);

            assertEquals(expectedPresentationResponseDTO, actualPresentationResponseDTO);
        }
    }

    @Test
    public void testHandleVPAuthorizationRequest_untrustedVerifier() throws Exception {
        try (MockedStatic<UUID> mockedStatic = mockStatic(UUID.class);
             MockedStatic<Instant> mockedInstant = mockStatic(Instant.class)) {

            mockedStatic.when(UUID::randomUUID).thenReturn(fixedUuid);
            mockedInstant.when(Instant::now).thenReturn(fixedInstant);

            when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
            when(verifierService.isVerifierTrustedByWallet(clientId, walletId)).thenReturn(false);

            OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
            when(openID4VPFactory.create(anyString())).thenReturn(mockOpenID4VP);
            when(mockOpenID4VP.authenticateVerifier(urlEncodedVPAuthorizationRequest, preRegisteredVerifiers))
                    .thenReturn(getPresentationAuthorizationRequest(clientId, "https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fvp-response"));

            VerifiablePresentationResponseDTO expectedPresentationResponseDTO = getVerifiablePresentationResponseDTO("test-clientId", "test-clientId", null, false, true, "https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fvp-response", mockOpenID4VP, fixedInstant);

            VerifiablePresentationResponseDTO actualPresentationResponseDTO =
                    presentationService.handleVPAuthorizationRequest(urlEncodedVPAuthorizationRequest, walletId);

            assertEquals(expectedPresentationResponseDTO, actualPresentationResponseDTO);
        }
    }

    @Test
    public void testHandleVPAuthorizationRequest_verifierNotPreRegisteredWithWallet() throws Exception {
        clientId = "unknown-clientId";
        try (MockedStatic<UUID> mockedStatic = mockStatic(UUID.class);
             MockedStatic<Instant> mockedInstant = mockStatic(Instant.class)) {

            mockedStatic.when(UUID::randomUUID).thenReturn(fixedUuid);
            mockedInstant.when(Instant::now).thenReturn(fixedInstant);

            when(verifierService.getTrustedVerifiers()).thenReturn(verifiersDTO);
            when(verifierService.isVerifierTrustedByWallet(clientId, walletId)).thenReturn(false);

            OpenID4VP mockOpenID4VP = mock(OpenID4VP.class);
            when(openID4VPFactory.create(anyString())).thenReturn(mockOpenID4VP);
            when(mockOpenID4VP.authenticateVerifier(urlEncodedVPAuthorizationRequest, preRegisteredVerifiers))
                    .thenReturn(getPresentationAuthorizationRequest(clientId, "https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fvp-response"));

            VerifiablePresentationResponseDTO expectedPresentationResponseDTO = getVerifiablePresentationResponseDTO("unknown-clientId", "unknown-clientId", null, false, false, "https%3A%2F%2Finji-verify.collab.mosip.net%2Fverifier%2Fvp-response", mockOpenID4VP, fixedInstant);

            VerifiablePresentationResponseDTO actualPresentationResponseDTO =
                    presentationService.handleVPAuthorizationRequest(urlEncodedVPAuthorizationRequest, walletId);

            assertEquals(expectedPresentationResponseDTO, actualPresentationResponseDTO);
        }
    }

    // Helper methods
    private VCCredentialResponse createSDJwtCredentialResponse(String format) {
        VCCredentialResponse response = new VCCredentialResponse();
        response.setFormat(format);
        response.setCredential("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.test.signature");
        return response;
    }

    private PresentationRequestDTO createSDJwtPresentationRequest() {
        PresentationRequestDTO request = new PresentationRequestDTO();
        request.setRedirectUri("test_redirect_uri");

        Map<String, Map<String, List<String>>> format = Map.of(
                "vc+sd-jwt", Map.of("sd-jwt_alg_values", Arrays.asList("ES256"))
        );

        InputDescriptorDTO inputDescriptor = InputDescriptorDTO.builder()
                .id("test-id")
                .format(format)
                .build();

        PresentationDefinitionDTO presentationDefinition = PresentationDefinitionDTO.builder()
                .id("test-presentation-def")
                .inputDescriptors(Arrays.asList(inputDescriptor))
                .build();

        request.setPresentationDefinition(presentationDefinition);
        return request;
    }

    private VCCredentialResponse createLdpVcCredentialResponse() {
        VCCredentialResponse response = new VCCredentialResponse();
        response.setFormat(CredentialFormat.LDP_VC.getFormat());

        VCCredentialProperties credential = new VCCredentialProperties();
        credential.setType(Arrays.asList("VerifiableCredential", "TestCredential"));
        credential.setContext("https://www.w3.org/2018/credentials/v1");

        VCCredentialResponseProof proof = new VCCredentialResponseProof();
        proof.setType("Ed25519Signature2020");
        credential.setProof(proof);

        response.setCredential(credential);
        return response;
    }
}
