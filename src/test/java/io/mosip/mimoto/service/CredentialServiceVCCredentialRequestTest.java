package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.util.*;
import lombok.extern.slf4j.Slf4j;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;
import static io.mosip.mimoto.util.TestUtilities.*;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;

@RunWith(MockitoJUnitRunner.class)
@SpringBootTest
@Slf4j
public class CredentialServiceVCCredentialRequestTest {
    @InjectMocks
    CredentialUtilService credentialUtilService;
    
    @Mock
    JoseUtil joseUtil;

    IssuerDTO issuerDTO;
    String issuerId;

    @Before
    public void setUp() throws Exception {
        issuerId = "issuer1";
        issuerDTO = getIssuerConfigDTO(issuerId);
    }

    @Test
    public void shouldHandleNullContextInCredentialSupportedResponse() throws Exception {
        CredentialsSupportedResponse credentialsSupportedResponse = getCredentialSupportedResponse("CredentialType1");
        credentialsSupportedResponse.getCredentialDefinition().setContext(null);

        CredentialIssuerWellKnownResponse issuerWellKnownResponse = new CredentialIssuerWellKnownResponse();
        issuerWellKnownResponse.setCredentialIssuer("https://example-issuer.com");

        Mockito.when(joseUtil.generateJwt(any(), any(), any())).thenReturn("jwt");

        VCCredentialRequest result = credentialUtilService.generateVCCredentialRequest(
                issuerDTO,
                issuerWellKnownResponse,
                credentialsSupportedResponse,
                "test-access-token",
                "walletId",
                "walletKey",
                false
        );

        System.out.println("Result: " + result);

        assertNotNull(result.getCredentialDefinition().getContext());
        assertEquals("https://www.w3.org/2018/credentials/v1", result.getCredentialDefinition().getContext().get(0));
    }
    
    @Test
    public void shouldHandleEmptyContextInCredentialSupportedResponse() throws Exception {
        CredentialsSupportedResponse credentialsSupportedResponse = getCredentialSupportedResponse("CredentialType1");

        // Set an empty list as context
        credentialsSupportedResponse.getCredentialDefinition().setContext(List.of());

        CredentialIssuerWellKnownResponse issuerWellKnownResponse = new CredentialIssuerWellKnownResponse();
        issuerWellKnownResponse.setCredentialIssuer("https://example-issuer.com");

        Mockito.when(joseUtil.generateJwt(any(), any(), any())).thenReturn("jwt");

        VCCredentialRequest result = credentialUtilService.generateVCCredentialRequest(
                issuerDTO,
                issuerWellKnownResponse,
                credentialsSupportedResponse,
                "test-access-token",
                "walletId",
                "walletKey",
                false
        );

        System.out.println("Result: " + result);

        assertNotNull(result.getCredentialDefinition().getContext());
        assertEquals("https://www.w3.org/2018/credentials/v1", result.getCredentialDefinition().getContext().get(0));
    }
    

    @Test
    public void shouldHandleExistingContextWithSpecificValue() throws Exception {
        CredentialsSupportedResponse credentialsSupportedResponse = getCredentialSupportedResponse("CredentialType1");

        // Set context with a specific value
        credentialsSupportedResponse.getCredentialDefinition().setContext(List.of("https://www.w3.org/ns/credentials/v2"));

        CredentialIssuerWellKnownResponse issuerWellKnownResponse = new CredentialIssuerWellKnownResponse();
        issuerWellKnownResponse.setCredentialIssuer("https://example-issuer.com");

        Mockito.when(joseUtil.generateJwt(any(), any(), any())).thenReturn("jwt");

        VCCredentialRequest result = credentialUtilService.generateVCCredentialRequest(
                issuerDTO,
                issuerWellKnownResponse,
                credentialsSupportedResponse,
                "test-access-token",
                "walletId",
                "walletKey",
                false
        );

        assertNotNull(result.getCredentialDefinition().getContext());
        assertEquals("https://www.w3.org/ns/credentials/v2", result.getCredentialDefinition().getContext().get(0));
    }

}