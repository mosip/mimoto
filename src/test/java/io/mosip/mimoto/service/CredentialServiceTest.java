package io.mosip.mimoto.service;

import com.google.gson.Gson;
import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.dto.LogoDTO;
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

import static io.mosip.mimoto.service.IssuersServiceTest.getIssuerDTO;
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
        issuers.setIssuers(List.of(getIssuerDTO("Issuer1", Collections.emptyList()), getIssuerDTO("Issuer2", Collections.emptyList())));
        Mockito.when(issuersService.getAllIssuersWithAllFields()).thenReturn(issuers);
    }
    static CredentialsSupportedResponse getCredentialSupportedResponse(String credentialSupportedName){
        LogoDTO logo = new LogoDTO();
        logo.setUrl("/logo");
        logo.setAlt_text("logo-url");
        CredentialSupportedDisplayResponse credentialSupportedDisplay = new CredentialSupportedDisplayResponse();
        credentialSupportedDisplay.setLogo(logo);
        credentialSupportedDisplay.setName(credentialSupportedName);
        credentialSupportedDisplay.setLocale("en");
        credentialSupportedDisplay.setTextColor("#FFFFFF");
        credentialSupportedDisplay.setBackgroundColor("#B34622");
        CredentialIssuerDisplayResponse credentialIssuerDisplayResponse = new CredentialIssuerDisplayResponse();
        credentialIssuerDisplayResponse.setName("Given Name");
        credentialIssuerDisplayResponse.setLocale("en");
        CredentialDisplayResponseDto credentialDisplayResponseDto = new CredentialDisplayResponseDto();
        credentialDisplayResponseDto.setDisplay(Collections.singletonList(credentialIssuerDisplayResponse));
        CredentialDefinitionResponseDto credentialDefinitionResponseDto = new CredentialDefinitionResponseDto();
        credentialDefinitionResponseDto.setType(List.of("VerifiableCredential", credentialSupportedName));
        credentialDefinitionResponseDto.setCredentialSubject(Map.of("name", credentialDisplayResponseDto));
        CredentialsSupportedResponse credentialsSupportedResponse = new CredentialsSupportedResponse();
        credentialsSupportedResponse.setFormat("ldp_vc");
        credentialsSupportedResponse.setId(credentialSupportedName+"id");
        credentialsSupportedResponse.setScope(credentialSupportedName+"_vc_ldp");
        credentialsSupportedResponse.setDisplay(Collections.singletonList(credentialSupportedDisplay));
        credentialsSupportedResponse.setProofTypesSupported(Collections.singletonList("jwt"));
        credentialsSupportedResponse.setCredentialDefinition(credentialDefinitionResponseDto);
        return credentialsSupportedResponse;
    }

    static CredentialIssuerWellKnownResponse getCredentialIssuerWellKnownResponseDto(String issuerName, List<CredentialsSupportedResponse> credentialsSupportedResponses){
        CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse = new CredentialIssuerWellKnownResponse();
        credentialIssuerWellKnownResponse.setCredentialIssuer(issuerName);
        credentialIssuerWellKnownResponse.setCredentialEndPoint("/credential_endpoint");
        credentialIssuerWellKnownResponse.setCredentialsSupported(credentialsSupportedResponses);
        return credentialIssuerWellKnownResponse;
    }

    @Test
    public void shouldReturnIssuerCredentialSupportedResponseForTheIssuerIdIfExist() throws Exception {
        IssuerSupportedCredentialsResponse expectedIssuerCredentialsSupported = new IssuerSupportedCredentialsResponse();
        List<CredentialsSupportedResponse> credentialsSupportedResponses =List.of(getCredentialSupportedResponse("CredentialSupported1"),
                getCredentialSupportedResponse("CredentialSupported2"));

        String authorization_endpoint = getIssuerDTO("Issuer1", issuerConfigRelatedFields).getAuthorization_endpoint();
        expectedIssuerCredentialsSupported.setSupportedCredentials(credentialsSupportedResponses);
        expectedIssuerCredentialsSupported.setAuthorizationEndPoint(authorization_endpoint);

        Mockito.when(restApiClient.getApi(any(String.class), any())).thenReturn(getCredentialIssuerWellKnownResponseDto("Issuer1",
                List.of(getCredentialSupportedResponse("CredentialSupported1"), getCredentialSupportedResponse("CredentialSupported2"))));
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
