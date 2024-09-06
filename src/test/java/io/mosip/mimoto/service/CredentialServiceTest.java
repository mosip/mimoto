package io.mosip.mimoto.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.VCVerificationException;
import io.mosip.mimoto.service.impl.CredentialServiceImpl;
import io.mosip.mimoto.service.impl.IssuersServiceImpl;
import io.mosip.mimoto.util.RestApiClient;
import io.mosip.mimoto.util.TestUtilities;
import io.mosip.mimoto.util.Utilities;
import io.mosip.vercred.CredentialsVerifier;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.IOException;
import java.io.StringWriter;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static io.mosip.mimoto.util.TestUtilities.*;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;

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
        Mockito.when(credentialsVerifier.verifyCredentials(any(String.class))).thenReturn(true);
        Mockito.when(objectMapper.writeValueAsString(vc.getCredential())).thenReturn("vc");

        Boolean verificationStatus = credentialService.verifyCredential(vc);

        assertTrue(verificationStatus);
    }
}
