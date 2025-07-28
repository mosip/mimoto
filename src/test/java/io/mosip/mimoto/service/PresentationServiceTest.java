package io.mosip.mimoto.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.mimoto.VCCredentialProperties;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.openid.presentation.PresentationRequestDTO;
import io.mosip.mimoto.exception.VPNotCreatedException;
import io.mosip.mimoto.service.impl.DataShareServiceImpl;
import io.mosip.mimoto.service.impl.PresentationServiceImpl;
import io.mosip.mimoto.service.impl.VerifierServiceImpl;
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
    VerifierService verifierService = new VerifierServiceImpl();
    @Mock
    DataShareServiceImpl dataShareService;
    @Mock
    ObjectMapper objectMapper;

    @InjectMocks
    PresentationServiceImpl presentationService;

    @Before
    public void setup() throws JsonProcessingException {
        ReflectionTestUtils.setField(presentationService, "injiOvpRedirectURLPattern", "%s#vp_token=%s&presentation_submission=%s");
        ReflectionTestUtils.setField(presentationService, "dataShareUrl", "test_resource");
        ReflectionTestUtils.setField(presentationService, "maximumResponseHeaderSize", 65536);
        when(objectMapper.writeValueAsString(any())).thenReturn("test-data");
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
}
