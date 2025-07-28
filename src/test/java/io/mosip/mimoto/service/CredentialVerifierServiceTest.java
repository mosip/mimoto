package io.mosip.mimoto.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.mimoto.VCCredentialProperties;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponseProof;
import io.mosip.mimoto.exception.VCVerificationException;
import io.mosip.mimoto.service.impl.CredentialVerifierServiceImpl;
import io.mosip.vercred.vcverifier.CredentialsVerifier;
import io.mosip.vercred.vcverifier.constants.CredentialFormat;
import io.mosip.vercred.vcverifier.data.VerificationResult;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.Arrays;
import java.util.Map;

import static org.mockito.Mockito.*;
import static org.junit.Assert.*;

@RunWith(MockitoJUnitRunner.class)
public class CredentialVerifierServiceTest {

    @InjectMocks
    private CredentialVerifierServiceImpl credentialVerifier;

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private CredentialsVerifier credentialsVerifier;

    @Mock
    private VerificationResult verificationResult;

    private VCCredentialResponse vcCredentialResponse;

    private final String credentialJson = "{\"credential\":\"test\"}";

    @Before
    public void setUp() throws Exception {
        VCCredentialProperties credentialProperties = VCCredentialProperties.builder()
                .type(Arrays.asList("VerifiableCredential", "test"))
                .credentialSubject(Map.of("name", "John Doe"))
                .proof(new VCCredentialResponseProof())
                .build();

        vcCredentialResponse = VCCredentialResponse.builder()
                .format(CredentialFormat.LDP_VC.getValue())
                .credential(credentialProperties)
                .build();

        when(objectMapper.writeValueAsString(any())).thenReturn(credentialJson);
    }

    @Test
    public void testVerifySuccess() throws Exception {
        // Arrange
        when(credentialsVerifier.verify(eq(credentialJson), eq(CredentialFormat.LDP_VC))).thenReturn(verificationResult);
        when(verificationResult.getVerificationStatus()).thenReturn(true);

        // Act
        boolean result = credentialVerifier.verify(vcCredentialResponse);

        // Assert
        assertTrue(result);
        verify(credentialsVerifier).verify(credentialJson, CredentialFormat.LDP_VC);
    }

    @Test(expected = VCVerificationException.class)
    public void testVerifyFailureThrowsException() throws Exception {
        // Arrange
        when(credentialsVerifier.verify(eq(credentialJson), eq(CredentialFormat.LDP_VC))).thenReturn(verificationResult);
        when(verificationResult.getVerificationStatus()).thenReturn(false);
        when(verificationResult.getVerificationErrorCode()).thenReturn("ERR_CODE");
        when(verificationResult.getVerificationMessage()).thenReturn("Verification failed");

        // Act
        credentialVerifier.verify(vcCredentialResponse);
    }

    @Test(expected = JsonProcessingException.class)
    public void testVerifyJsonProcessingException() throws Exception {
        // Arrange
        when(objectMapper.writeValueAsString(any())).thenThrow(JsonProcessingException.class);

        // Act
        credentialVerifier.verify(vcCredentialResponse);
    }

    @Test(expected = NullPointerException.class)
    public void testVerifyWithNullCredential() throws Exception {
        // Arrange
        VCCredentialResponse nullCredentialResponse = VCCredentialResponse.builder()
                .format(CredentialFormat.LDP_VC.getValue())
                .credential(null)
                .build();

        // Act
        credentialVerifier.verify(nullCredentialResponse);
    }
}
