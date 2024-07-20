package io.mosip.mimoto.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.openid.presentation.PresentationDefinitionDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationRequestDTO;
import io.mosip.mimoto.dto.openid.presentation.VerifiablePresentationDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.InvalidVerifierException;
import io.mosip.mimoto.exception.VPNotCreatedException;
import io.mosip.mimoto.service.impl.PresentationServiceImpl;
import io.mosip.mimoto.service.impl.VerifiersServiceImpl;
import io.mosip.mimoto.util.RestApiClient;
import io.mosip.mimoto.util.TestUtilities;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class PresentationServiceTest {
    @Mock
    VerifiersService verifiersService = new VerifiersServiceImpl();
    @Mock
    RestApiClient restApiClient;
    @Mock
    ObjectMapper objectMapper;

    @InjectMocks
    PresentationServiceImpl presentationService;

    @Before
    public void setup() throws JsonProcessingException {
        PresentationDefinitionDTO presentationDefinitionDTO = TestUtilities.getPresentationDefinitionDTO();
        ReflectionTestUtils.setField(presentationService, "injiVerifyRedirectUrl", "%s#vp_token=%s&presentation_submission=%s");
        when(objectMapper.readValue(eq(TestUtilities.getObjectAsString(presentationDefinitionDTO)), eq(PresentationDefinitionDTO.class))).thenReturn(presentationDefinitionDTO);
        when(objectMapper.writeValueAsString(any())).thenReturn("test-data");
    }
    @Test(expected = InvalidVerifierException.class)
    public void throwInvalidVerifierExceptionWhenClientIdPassedIsIncorrect() throws ApiNotAccessibleException, IOException {
        PresentationRequestDTO presentationRequestDTO = TestUtilities.getPresentationRequestDTO();
        doThrow(InvalidVerifierException.class).when(verifiersService).validateVerifier(presentationRequestDTO);
        presentationService.authorizePresentation(TestUtilities.getPresentationRequestDTO());
    }

    @Test
    public void credentialProofMatchingWithVPRequest() throws Exception {

        String mockResponse = TestUtilities.getObjectAsString(TestUtilities.getVCCredentialResponseDTO("Ed25519Signature2020"));
        VCCredentialResponse vcCredentialResponse = TestUtilities.getVCCredentialResponseDTO("Ed25519Signature2020");
        VerifiablePresentationDTO verifiablePresentationDTO = TestUtilities.getVerifiablePresentationDTO();
        PresentationRequestDTO presentationRequestDTO = TestUtilities.getPresentationRequestDTO();

        doNothing().when(verifiersService).validateVerifier(eq(presentationRequestDTO));
        when(restApiClient.getApi(eq(presentationRequestDTO.getResource()), eq(String.class))).thenReturn(mockResponse);
        when(objectMapper.readValue(eq(TestUtilities.getObjectAsString(vcCredentialResponse)), eq(VCCredentialResponse.class))).thenReturn(vcCredentialResponse);
        when(objectMapper.readValue(eq("test-data"), eq(VerifiablePresentationDTO.class))).thenReturn(verifiablePresentationDTO);

        String actualRedirectUrl = presentationService.authorizePresentation(TestUtilities.getPresentationRequestDTO());
        String expectedRedirectUrl = "test_redirect_uri#vp_token=dGVzdC1kYXRh&presentation_submission=test-data";

        assertEquals(expectedRedirectUrl, actualRedirectUrl);
    }

    @Test(expected = VPNotCreatedException.class)
    public void credentialProofMismatchWithVPRequest() throws ApiNotAccessibleException, IOException {

        String mockResponse = TestUtilities.getObjectAsString(TestUtilities.getVCCredentialResponseDTO("RSASignature2020"));
        VCCredentialResponse vcCredentialResponse = TestUtilities.getVCCredentialResponseDTO("RSASignature2020");
        PresentationRequestDTO presentationRequestDTO = TestUtilities.getPresentationRequestDTO();

        doNothing().when(verifiersService).validateVerifier(eq(presentationRequestDTO));
        when(restApiClient.getApi(eq(presentationRequestDTO.getResource()), eq(String.class))).thenReturn(mockResponse);
        when(objectMapper.readValue(eq(TestUtilities.getObjectAsString(vcCredentialResponse)), eq(VCCredentialResponse.class))).thenReturn(vcCredentialResponse);

        presentationService.authorizePresentation(TestUtilities.getPresentationRequestDTO());
    }
}
