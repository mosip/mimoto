package io.mosip.mimoto.service;

import com.google.gson.Gson;
import io.mosip.mimoto.dto.DisplayDTO;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.dto.LogoDTO;
import io.mosip.mimoto.dto.v2.*;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.service.impl.V2IssuersServiceImpl;
import io.mosip.mimoto.util.RestApiClient;
import io.mosip.mimoto.util.Utilities;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

@RunWith(PowerMockRunner.class)
@SpringBootTest
public class V2IssuersServiceTest {

    @InjectMocks
    V2IssuersServiceImpl v2IssuersService = new V2IssuersServiceImpl();

    @Mock
    Utilities utilities;

    @Mock
    public RestApiClient restApiClient;

    static IssuerDTO getIssuerDTO(String issuerName) {
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
        issuer.setWellKnownEndpoint("/.well-known");
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
        issuers.setIssuers(List.of(getIssuerDTO("Issuer1")));
        CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse = getCredentialIssuerWellKnownResponseDto("Issuer1",
                List.of(getCredentialSupportedResponse("CredentialSupported1"), getCredentialSupportedResponse("CredentialSupported2")));
        Mockito.when(utilities.getV2CredentialsSupportedConfigJsonValue()).thenReturn(new Gson().toJson(credentialIssuerWellKnownResponse));
        Mockito.when(utilities.getIssuersConfigJsonValue()).thenReturn(new Gson().toJson(issuers));
    }

    @Test(expected = ApiNotAccessibleException.class)
    public void shouldThrowApiNotAccessibleExceptionWhenIssuersDtoIsNullForGettingIssuersLIst() throws IOException, ApiNotAccessibleException {
        Mockito.when(utilities.getIssuersConfigJsonValue()).thenReturn(null);
        v2IssuersService.getAllIssuers(null);
    }

    @Test
    public void shouldReturnIssuersWithIssuerConfig() throws ApiNotAccessibleException, IOException {
        IssuersDTO expectedIssuers = new IssuersDTO();
        List<IssuerDTO> issuers = new ArrayList<>(List.of(getIssuerDTO("Issuer1")));
        expectedIssuers.setIssuers(issuers);

        IssuersDTO allIssuers = v2IssuersService.getAllIssuers(null);

        assertEquals(expectedIssuers, allIssuers);
    }

    @Test
    public void shouldReturnNullIfTheIssuerIdNotExistsForIssuerList() throws ApiNotAccessibleException, IOException {
        IssuersDTO issuers = v2IssuersService.getAllIssuers("Issuer2");
        assertTrue(issuers.getIssuers().isEmpty());
    }


    @Test(expected = ApiNotAccessibleException.class)
    public void shouldThrowApiNotAccessibleExceptionWhenCredentialsSupportedJsonStringIsNullForGettingCredentialsSupportedList() throws Exception {
        Mockito.when(utilities.getV2CredentialsSupportedConfigJsonValue()).thenReturn(null);
        Mockito.when(restApiClient.getApi(Mockito.any(URI.class), Mockito.any(Class.class))).thenReturn(null);
        v2IssuersService.getCredentialsSupported("Issuer1id", null);
    }

    @Test
    public void shouldReturnIssuerCredentialSupportedResponseForTheIssuerIdIfExist() throws Exception {
        IssuerSupportedCredentialsResponse expectedIssuerCredentialsSupported = new IssuerSupportedCredentialsResponse();
       List<CredentialsSupportedResponse> credentialsSupportedResponses =List.of(getCredentialSupportedResponse("CredentialSupported1"),
               getCredentialSupportedResponse("CredentialSupported2"));

       String authorization_endpoint = getIssuerDTO("Issuer1").getAuthorization_endpoint();
       expectedIssuerCredentialsSupported.setSupportedCredentials(credentialsSupportedResponses);
       expectedIssuerCredentialsSupported.setAuthorization_endpoint(authorization_endpoint);

        Mockito.when(restApiClient.getApi(Mockito.any(URI.class), Mockito.any(Class.class))).thenReturn(null);
        IssuerSupportedCredentialsResponse issuerSupportedCredentialsResponse = v2IssuersService.getCredentialsSupported("Issuer1id", null);
        assertEquals(issuerSupportedCredentialsResponse, expectedIssuerCredentialsSupported);
    }

    @Test
    public void shouldReturnNullIfTheIssuerIdNotExists() throws ApiNotAccessibleException, IOException {
        IssuerSupportedCredentialsResponse issuerSupportedCredentialsResponse = v2IssuersService.getCredentialsSupported("Issuer3id", null);
        assertNull(issuerSupportedCredentialsResponse.getSupportedCredentials());
        assertNull(issuerSupportedCredentialsResponse.getAuthorization_endpoint());
    }

    @Test
    public void shouldParseHtmlStringToDocument() {
        String htmlContent = "<html><body><h1>Hello World!</h1></body></html>";
        Document doc = Jsoup.parse(htmlContent);
        assertNotNull(doc);
    }

}
