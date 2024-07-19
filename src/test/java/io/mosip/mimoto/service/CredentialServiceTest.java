package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.service.impl.CredentialServiceImpl;
import io.mosip.mimoto.service.impl.IssuersServiceImpl;
import io.mosip.mimoto.util.RestApiClient;
import io.mosip.mimoto.util.Utilities;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;
import org.junit.Before;
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

@RunWith(MockitoJUnitRunner.class)
@SpringBootTest
public class CredentialServiceTest {

    @Mock
    IssuersService issuersService = new IssuersServiceImpl();
    @InjectMocks
    CredentialServiceImpl credentialService = new CredentialServiceImpl();

    @Mock
    Utilities utilities;

    @Mock
    public RestApiClient restApiClient;

    List<String> issuerConfigRelatedFields = List.of("additional_headers", "authorization_endpoint","authorization_audience", "token_endpoint", "proxy_token_endpoint", "credential_endpoint", "credential_audience", "redirect_uri");

    @Before
    public void setUp() throws Exception {
        IssuersDTO issuers = new IssuersDTO();
        issuers.setIssuers(List.of(getIssuerConfigDTO("Issuer1", Collections.emptyList()), getIssuerConfigDTO("Issuer2", Collections.emptyList())));
        Mockito.when(issuersService.getAllIssuersWithAllFields()).thenReturn(issuers);
    }

    @Test
    public void shouldReturnIssuerCredentialSupportedResponseForTheIssuerIdIfExist() throws Exception {
        IssuerSupportedCredentialsResponse expectedIssuerCredentialsSupported = new IssuerSupportedCredentialsResponse();
        List<CredentialsSupportedResponseDraft11> credentialsSupportedResponsDraft11s =List.of(getCredentialSupportedResponseDraft11("CredentialSupported1"),
                getCredentialSupportedResponseDraft11("CredentialSupported2"));

        String authorization_endpoint = getIssuerConfigDTO("Issuer1", issuerConfigRelatedFields).getAuthorization_endpoint();
        expectedIssuerCredentialsSupported.setSupportedCredentials(credentialsSupportedResponsDraft11s);
        expectedIssuerCredentialsSupported.setAuthorizationEndPoint(authorization_endpoint);

        Mockito.when(restApiClient.getApi(any(String.class), any())).thenReturn(getCredentialIssuerWellKnownResponseDtoDraft11("Issuer1",
                List.of(getCredentialSupportedResponseDraft11("CredentialSupported1"), getCredentialSupportedResponseDraft11("CredentialSupported2"))));
        IssuerSupportedCredentialsResponse issuerSupportedCredentialsResponse = credentialService.getCredentialsSupported("Issuer1id", null);
        assertEquals(issuerSupportedCredentialsResponse, expectedIssuerCredentialsSupported);
    }

    @Test
    public void shouldReturnNullIfTheIssuerIdNotExistsForCredentialSupportedTypes() throws ApiNotAccessibleException, IOException {
        IssuerSupportedCredentialsResponse issuerSupportedCredentialsResponse = credentialService.getCredentialsSupported("Issuer3id", null);
        assertNull(issuerSupportedCredentialsResponse.getSupportedCredentials());
        assertNull(issuerSupportedCredentialsResponse.getAuthorizationEndPoint());
    }

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


    @Test(expected = ApiNotAccessibleException.class)
    public void shouldThrowApiNotAccessibleExceptionWhenCredentialsSupportedJsonStringIsNullForGettingCredentialsSupportedList() throws Exception {
        Mockito.when(restApiClient.getApi(any(String.class), any(Class.class))).thenReturn(null);
        credentialService.getCredentialsSupported("Issuer1id", null);
    }
}
