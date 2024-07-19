package io.mosip.mimoto.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.openid.VerifierDTO;
import io.mosip.mimoto.dto.openid.VerifiersDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationRequestDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.InvalidVerifierException;
import io.mosip.mimoto.service.impl.VerifiersServiceImpl;
import io.mosip.mimoto.util.TestUtilities;
import io.mosip.mimoto.util.Utilities;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.IOException;
import java.util.Optional;

import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class VerifierServiceTest {

    @Mock
    Utilities utilities;
    @Mock
    ObjectMapper objectMapper;
    @InjectMocks
    VerifiersServiceImpl verifiersService;

    @Before
    public void setUp() throws JsonProcessingException {
        VerifiersDTO verifiersDTO = TestUtilities.getTrustedVerifiers();
        String verifiersListString = TestUtilities.getObjectAsString(verifiersDTO);
        when(utilities.getTrustedVerifiersJsonValue()).thenReturn(verifiersListString);
        Mockito.when(objectMapper.readValue(Mockito.eq(verifiersListString), Mockito.eq(VerifiersDTO.class))).thenReturn(verifiersDTO);
    }

    @Test
    public void getCorrectVerifierWhenCorrectClientIdIsPassed() throws ApiNotAccessibleException, IOException {
        Optional<VerifierDTO> verifierDTO = verifiersService.getVerifiersByClientId("test-clientId");
        Assert.assertNotNull(verifierDTO.get());
        Assert.assertEquals(verifierDTO.get().getClientId(), "test-clientId");
    }

    @Test
    public void getNullWhenInvalidClientIdIsPassed() throws ApiNotAccessibleException, IOException {
        Optional<VerifierDTO> verifierDTO = verifiersService.getVerifiersByClientId("test-clientId2");
        Assert.assertTrue(verifierDTO.isEmpty());
    }

    @Test
    public void validateTrustedVerifiersAndDoNothing() throws ApiNotAccessibleException, IOException {
        PresentationRequestDTO presentationRequestDTO = new PresentationRequestDTO();
        presentationRequestDTO.setClient_id("test-clientId");
        presentationRequestDTO.setRedirect_uri("test-redirectUri");
        verifiersService.validateVerifier(presentationRequestDTO);
    }

    @Test(expected = InvalidVerifierException.class)
    public void validateTrustedVerifiersAndThrowInvalidVerifierExceptionWhenClientIdIsIncorrect() throws ApiNotAccessibleException, IOException {
        PresentationRequestDTO presentationRequestDTO = new PresentationRequestDTO();
        presentationRequestDTO.setClient_id("test-clientId2");
        presentationRequestDTO.setRedirect_uri("test-redirectUri");
        verifiersService.validateVerifier(presentationRequestDTO);
    }

    @Test(expected = InvalidVerifierException.class)
    public void validateTrustedVerifiersAndThrowInvalidVerifiersExceptionWhenRedirectUriIsIncorrect() throws ApiNotAccessibleException, IOException {
        PresentationRequestDTO presentationRequestDTO = new PresentationRequestDTO();
        presentationRequestDTO.setClient_id("test-clientId");
        presentationRequestDTO.setRedirect_uri("test-redirectUri2");
        verifiersService.validateVerifier(presentationRequestDTO);
    }
}
