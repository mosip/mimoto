package io.mosip.mimoto.service;

import com.google.gson.Gson;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.dto.DisplayDTO;
import io.mosip.mimoto.dto.LogoDTO;
import io.mosip.mimoto.dto.mimoto.CredentialDefinitionResponseDto;
import io.mosip.mimoto.dto.mimoto.CredentialDisplayResponseDto;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerDisplayResponse;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.CredentialSupportedDisplayResponse;
import io.mosip.mimoto.dto.mimoto.CredentialsSupportedResponse;
import io.mosip.mimoto.dto.mimoto.IssuerSupportedCredentialsResponse;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
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
import java.net.URI;
import java.util.*;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
@SpringBootTest
public class IssuersServiceTest {

    @InjectMocks
    IssuersServiceImpl issuersService = new IssuersServiceImpl();

    @Mock
    Utilities utilities;

    @Mock
    public RestApiClient restApiClient;

    List<String> issuerConfigRelatedFields = List.of("additional_headers", "authorization_endpoint","authorization_audience", "token_endpoint", "proxy_token_endpoint", "credential_endpoint", "credential_audience", "redirect_uri");


    static IssuerDTO getIssuerDTO(String issuerName, List<String> nullFields) {
        LogoDTO logo = new LogoDTO();
        logo.setUrl("/logo");
        logo.setAlt_text("logo-url");
        DisplayDTO display = new DisplayDTO();
        display.setName(issuerName);
        display.setLanguage("en");
        display.setLogo(logo);
        IssuerDTO issuer = new IssuerDTO();
        issuer.setCredential_issuer(issuerName + "id");
        issuer.setDisplay(Collections.singletonList(display));
        issuer.setClient_id("123");
        if (issuerName.equals("Issuer1")) issuer.setWellKnownEndpoint("/.well-known");
        else {
            if (!nullFields.contains("redirect_uri"))
                issuer.setRedirect_uri("/redirection");
            if (!nullFields.contains("authorization_audience"))
                issuer.setAuthorization_audience("/authorization_audience");
            if (!nullFields.contains("redirect_uri"))
                issuer.setRedirect_uri("/redirection");
            if (!nullFields.contains("authorization_endpoint"))
                issuer.setAuthorization_endpoint("/authorization_endpoint");
            if (!nullFields.contains("token_endpoint"))
                issuer.setToken_endpoint("/token_endpoint");
            if (!nullFields.contains("proxy_token_endpoint"))
                issuer.setProxy_token_endpoint("/proxy_token_endpoint");
            if (!nullFields.contains("credential_endpoint"))
                issuer.setCredential_endpoint("/credential_endpoint");
            if (!nullFields.contains("credential_audience"))
                issuer.setCredential_audience("/credential_audience");
            if (!nullFields.contains("additional_headers"))
                issuer.setAdditional_headers(Map.of("Content-Type", "application/json"));
        }
        return issuer;
    }

    static CredentialsSupportedResponse getCredentialSupportedResponse(String credentialSupportedName){
        LogoDTO logo = new LogoDTO();
        logo.setUrl("/logo");
        logo.setAlt_text("logo-url");
        CredentialSupportedDisplayResponse credentialSupportedDisplay = new CredentialSupportedDisplayResponse();
        credentialSupportedDisplay.setLogo(logo);
        credentialSupportedDisplay.setName(credentialSupportedName);
        credentialSupportedDisplay.setLocale("en");
        credentialSupportedDisplay.setText_color("#FFFFFF");
        credentialSupportedDisplay.setBackground_color("#B34622");
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
        credentialsSupportedResponse.setProof_types_supported(Collections.singletonList("jwt"));
        credentialsSupportedResponse.setCredential_definition(credentialDefinitionResponseDto);
        return credentialsSupportedResponse;
    }

    static CredentialIssuerWellKnownResponse getCredentialIssuerWellKnownResponseDto(String issuerName, List<CredentialsSupportedResponse> credentialsSupportedResponses){
        CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse = new CredentialIssuerWellKnownResponse();
        credentialIssuerWellKnownResponse.setCredential_issuer(issuerName);
        credentialIssuerWellKnownResponse.setCredential_endpoint("/credential_endpoint");
        credentialIssuerWellKnownResponse.setCredentials_supported(credentialsSupportedResponses);
        return credentialIssuerWellKnownResponse;
    }

    @Before
    public void setUp() throws Exception {
        IssuersDTO issuers = new IssuersDTO();
        issuers.setIssuers(List.of(getIssuerDTO("Issuer1", Collections.emptyList()), getIssuerDTO("Issuer2", Collections.emptyList())));
        CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse = getCredentialIssuerWellKnownResponseDto("Issuer1",
                List.of(getCredentialSupportedResponse("CredentialSupported1"), getCredentialSupportedResponse("CredentialSupported2")));
        when(utilities.getCredentialsSupportedConfigJsonValue()).thenReturn(new Gson().toJson(credentialIssuerWellKnownResponse));
        when(utilities.getIssuersConfigJsonValue()).thenReturn(new Gson().toJson(issuers));
    }

    @Test
    public void shouldReturnIssuersWithIssuerConfigAsNull() throws ApiNotAccessibleException, IOException {
        IssuersDTO expectedIssuers = new IssuersDTO();
        List<IssuerDTO> issuers = new ArrayList<>(List.of(getIssuerDTO("Issuer1", issuerConfigRelatedFields), getIssuerDTO("Issuer2", issuerConfigRelatedFields)));
        expectedIssuers.setIssuers(issuers);

        IssuersDTO expectedFilteredIssuers = new IssuersDTO();
        List<IssuerDTO> filteredIssuersList = new ArrayList<>(List.of(getIssuerDTO("Issuer1", issuerConfigRelatedFields)));
        expectedFilteredIssuers.setIssuers(filteredIssuersList);

        IssuersDTO allIssuers = issuersService.getAllIssuers(null);
        IssuersDTO filteredIssuers = issuersService.getAllIssuers("Issuer1");
        assertEquals(expectedIssuers, allIssuers);
        assertEquals(expectedFilteredIssuers, filteredIssuers);
    }

    @Test(expected = ApiNotAccessibleException.class)
    public void shouldThrowApiNotAccessibleExceptionWhenIssuersJsonStringIsNullForGettingAllIssuers() throws IOException, ApiNotAccessibleException {
        when(utilities.getIssuersConfigJsonValue()).thenReturn(null);

        issuersService.getAllIssuers(null);
    }

    @Test
    public void shouldReturnIssuerDataAndConfigForTheIssuerIdIfExist() throws ApiNotAccessibleException, IOException {
        IssuerDTO expectedIssuer = getIssuerDTO("Issuer1", issuerConfigRelatedFields);

        IssuerDTO issuer = issuersService.getIssuerConfig("Issuer1id");

        assertEquals(expectedIssuer, issuer);
    }

    @Test
    public void shouldReturnIssuerDataAndConfigForAllIssuer() throws ApiNotAccessibleException, IOException {
        IssuersDTO expectedIssuers = new IssuersDTO();
        List<IssuerDTO> issuers = new ArrayList<>(List.of(getIssuerDTO("Issuer1", new ArrayList<>()), getIssuerDTO("Issuer2", new ArrayList<>())));
        expectedIssuers.setIssuers(issuers);

        IssuersDTO issuersDTO = issuersService.getAllIssuersWithAllFields();

        assertEquals(expectedIssuers, issuersDTO);
    }

    @Test
    public void shouldReturnNullIfTheIssuerIdNotExists() throws ApiNotAccessibleException, IOException {
        IssuerDTO issuer = issuersService.getIssuerConfig("Issuer3id");

        assertNull(issuer);
    }

    @Test(expected = ApiNotAccessibleException.class)
    public void shouldThrowApiNotAccessibleExceptionWhenIssuersJsonStringIsNullForGettingIssuerConfig() throws IOException, ApiNotAccessibleException {
        when(utilities.getIssuersConfigJsonValue()).thenReturn(null);

        issuersService.getIssuerConfig("Issuers1id");
    }

    @Test(expected = ApiNotAccessibleException.class)
    public void shouldThrowApiNotAccessibleExceptionWhenCredentialsSupportedJsonStringIsNullForGettingCredentialsSupportedList() throws Exception {
        when(utilities.getCredentialsSupportedConfigJsonValue()).thenReturn(null);
        when(restApiClient.getApi(Mockito.any(URI.class), Mockito.any(Class.class))).thenReturn(null);
        issuersService.getCredentialsSupported("Issuer1id", null);
    }

    @Test
    public void shouldReturnIssuerCredentialSupportedResponseForTheIssuerIdIfExist() throws Exception {
        IssuerSupportedCredentialsResponse expectedIssuerCredentialsSupported = new IssuerSupportedCredentialsResponse();
        List<CredentialsSupportedResponse> credentialsSupportedResponses =List.of(getCredentialSupportedResponse("CredentialSupported1"),
                getCredentialSupportedResponse("CredentialSupported2"));

        String authorization_endpoint = getIssuerDTO("Issuer1", issuerConfigRelatedFields).getAuthorization_endpoint();
        expectedIssuerCredentialsSupported.setSupportedCredentials(credentialsSupportedResponses);
        expectedIssuerCredentialsSupported.setAuthorization_endpoint(authorization_endpoint);

        when(restApiClient.getApi(Mockito.any(URI.class), Mockito.any(Class.class))).thenReturn(null);
        IssuerSupportedCredentialsResponse issuerSupportedCredentialsResponse = issuersService.getCredentialsSupported("Issuer1id", null);
        assertEquals(issuerSupportedCredentialsResponse, expectedIssuerCredentialsSupported);
    }

    @Test
    public void shouldReturnNullIfTheIssuerIdNotExistsForCredentialSupportedTypes() throws ApiNotAccessibleException, IOException {
        IssuerSupportedCredentialsResponse issuerSupportedCredentialsResponse = issuersService.getCredentialsSupported("Issuer3id", null);
        assertNull(issuerSupportedCredentialsResponse.getSupportedCredentials());
        assertNull(issuerSupportedCredentialsResponse.getAuthorization_endpoint());
    }

    @Test
    public void shouldParseHtmlStringToDocument() {
        String htmlContent = "<html><body><h1>$message</h1></body></html>";
        Map<String, Object> data = new HashMap<>();
        data.put("message", "PDF");
        // Create VelocityContext
        VelocityContext velocityContext = new VelocityContext();
        // Create StringWriter to capture output
        StringWriter writer = new StringWriter();
        // Merge template with data
        velocityContext.put("message", data.get("message"));
        Velocity.evaluate(velocityContext, writer, "Credential Template", htmlContent);
        // Get merged HTML
        String mergedHtml = writer.toString();
        // Assertion
        assertTrue(mergedHtml.contains("PDF"));
    }

}
