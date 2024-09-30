package io.mosip.mimoto.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.openid.VerifierDTO;
import io.mosip.mimoto.dto.openid.VerifiersDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationRequestDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.InvalidVerifierException;
import io.mosip.mimoto.service.impl.VerifierServiceImpl;
import io.mosip.mimoto.util.TestUtilities;
import io.mosip.mimoto.util.Utilities;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.IOException;
import java.util.Collections;
import java.util.Optional;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class VerifierServiceTest {

    @Mock
    Utilities utilities;
    @Mock
    ObjectMapper objectMapper;
    @InjectMocks
    VerifierServiceImpl verifiersService;

    @Before
    public void setUp() throws JsonProcessingException {
        VerifiersDTO verifiersDTO = TestUtilities.getTrustedVerifiers();
        String verifiersListString = TestUtilities.getObjectAsString(verifiersDTO);
        when(utilities.getTrustedVerifiersJsonValue()).thenReturn(verifiersListString);
        when(objectMapper.readValue(eq(verifiersListString), eq(VerifiersDTO.class))).thenReturn(verifiersDTO);
    }

    @Test
    public void shouldReturnAllTrustedIssuers() throws ApiNotAccessibleException, JsonProcessingException {
        VerifierDTO verifierDTO = VerifierDTO.builder()
                .clientId("test-clientId")
                .redirectUris(Collections.singletonList("https://test-redirectUri"))
                .responseUri(Collections.singletonList("https://test-responseUri")).build();
        VerifiersDTO expectedTrustedVerifiers = VerifiersDTO.builder()
                .verifiers(Collections.singletonList(verifierDTO)).build();

        VerifiersDTO actualTrustedVerifiers = verifiersService.getTrustedVerifiers();

        assertNotNull(actualTrustedVerifiers);
        assertEquals(actualTrustedVerifiers,expectedTrustedVerifiers);
    }

    @Test
    public void getCorrectVerifierWhenCorrectClientIdIsPassed() throws ApiNotAccessibleException, IOException {
        Optional<VerifierDTO> verifierDTO = verifiersService.getVerifierByClientId("test-clientId");
        assertNotNull(verifierDTO.get());
        assertEquals(verifierDTO.get().getClientId(), "test-clientId");
    }

    @Test
    public void getNullWhenInvalidClientIdIsPassed() throws ApiNotAccessibleException, IOException {
        Optional<VerifierDTO> verifierDTO = verifiersService.getVerifierByClientId("test-clientId2");
        assertTrue(verifierDTO.isEmpty());
    }

    @Test
    public void validateTrustedVerifiersAndDoNothing() throws ApiNotAccessibleException, IOException {
        PresentationRequestDTO presentationRequestDTO = PresentationRequestDTO.builder().clientId("test-clientId").redirectUri("https://test-redirectUri").build();
        verifiersService.validateVerifier(presentationRequestDTO.getClientId(), presentationRequestDTO.getRedirectUri());
    }

    @Test(expected = InvalidVerifierException.class)
    public void validateTrustedVerifiersAndThrowInvalidVerifierExceptionWhenClientIdIsIncorrect() throws ApiNotAccessibleException, IOException {
        PresentationRequestDTO presentationRequestDTO = PresentationRequestDTO.builder().clientId("test-clientId2").redirectUri("https://test-redirectUri").build();
        verifiersService.validateVerifier(presentationRequestDTO.getClientId(), presentationRequestDTO.getRedirectUri());
    }

    @Test(expected = InvalidVerifierException.class)
    public void validateTrustedVerifiersAndThrowInvalidVerifiersExceptionWhenRedirectUriIsIncorrect() throws ApiNotAccessibleException, IOException {
        PresentationRequestDTO presentationRequestDTO = PresentationRequestDTO.builder().clientId("test-clientId2").redirectUri("https://test-redirectUri").build();
        verifiersService.validateVerifier(presentationRequestDTO.getClientId(), presentationRequestDTO.getRedirectUri());
    }
}
