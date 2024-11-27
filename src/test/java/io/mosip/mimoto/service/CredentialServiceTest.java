package io.mosip.mimoto.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.exception.VCVerificationException;
import io.mosip.mimoto.service.impl.CredentialServiceImpl;
import io.mosip.mimoto.util.TestUtilities;
import io.mosip.vercred.vcverifier.CredentialsVerifier;
import io.mosip.vercred.vcverifier.constants.CredentialFormat;
import io.mosip.vercred.vcverifier.data.VerificationResult;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;

@RunWith(MockitoJUnitRunner.class)
@SpringBootTest
public class CredentialServiceTest {

    @Mock
    CredentialsVerifier credentialsVerifier;
    @Mock
    ObjectMapper objectMapper;
    @InjectMocks
    CredentialServiceImpl credentialService = new CredentialServiceImpl();


    @Test
    @Ignore
    public void shouldParseHtmlStringToDocument() {
        String htmlContent = "<html><body><h1>$message</h1></body></html>";
        Map<String, Object> data = new HashMap<>();
        data.put("message", "PDF");
        VelocityContext velocityContext = new VelocityContext();
        StringWriter writer = new StringWriter();
        velocityContext.put("message", data.get("message"));
        Velocity.evaluate(velocityContext, writer, "Credential Template", htmlContent);
        String mergedHtml = writer.toString();
        assertTrue(mergedHtml.contains("PDF"));
    }


    @Test
    @Ignore
    public void shouldReturnTrueIfAValidCredentialIsPassedForVerification() throws VCVerificationException, JsonProcessingException {
        VCCredentialResponse vc = TestUtilities.getVCCredentialResponseDTO("ed25519Signature2020");
        VerificationResult verificationResult = new VerificationResult(true, "", "");
        Mockito.when(credentialsVerifier.verify(any(String.class), eq(CredentialFormat.LDP_VC))).thenReturn(verificationResult);
        Mockito.when(objectMapper.writeValueAsString(vc.getCredential())).thenReturn("vc");
        Boolean verificationStatus = credentialService.verifyCredential(vc);
        assertTrue(verificationStatus);
    }
}
