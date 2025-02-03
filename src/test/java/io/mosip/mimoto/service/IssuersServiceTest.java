package io.mosip.mimoto.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerConfigurationResponse;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.AuthorizationServerWellknownResponseException;
import io.mosip.mimoto.exception.InvalidIssuerIdException;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import io.mosip.mimoto.service.impl.CredentialServiceImpl;
import io.mosip.mimoto.service.impl.IssuerWellknownServiceImpl;
import io.mosip.mimoto.service.impl.IssuersServiceImpl;
import io.mosip.mimoto.util.Utilities;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static io.mosip.mimoto.util.TestUtilities.*;
import static io.mosip.mimoto.util.TestUtilities.getCredentialSupportedResponse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@RunWith(MockitoJUnitRunner.class)
public class IssuersServiceTest {

    @InjectMocks
    IssuersServiceImpl issuersService = new IssuersServiceImpl();

    @InjectMocks
    CredentialServiceImpl credentialService = new CredentialServiceImpl();

    @Mock
    Utilities utilities;

    @Mock
    IssuerWellknownServiceImpl issuerWellknownService;

    @Mock
    AuthorizationServerService authorizationServerService;

    @Spy
    ObjectMapper objectMapper;

    List<String> issuerConfigRelatedFields = List.of("additional_headers", "authorization_endpoint", "authorization_audience", "credential_endpoint", "credential_audience");

    String issuerWellKnownUrl, issuerId, credentialIssuerHostUrl, authServerWellknownUrl, issuersConfigJsonValue;
    CredentialIssuerConfigurationResponse expectedCredentialIssuerConfigurationResponse;
    IssuersDTO issuers = new IssuersDTO();

    CredentialIssuerWellKnownResponse expectedCredentialIssuerWellKnownResponse;

    @Before
    public void setUp() throws Exception {
        issuerWellKnownUrl = "https://issuer.env.net/.well-known/openid-credential-issuer";
        authServerWellknownUrl = "https://auth-server.env.net";
        issuerId = "Issuer3id";
        credentialIssuerHostUrl = "https://issuer.env.net";

        issuers.setIssuers(List.of(getIssuerConfigDTO("Issuer3"), getIssuerConfigDTO("Issuer4")));
        issuersConfigJsonValue = new Gson().toJson(issuers);
        Mockito.when(utilities.getIssuersConfigJsonValue()).thenReturn(issuersConfigJsonValue);
        Mockito.when(objectMapper.readValue(issuersConfigJsonValue, IssuersDTO.class)).thenReturn(issuers);

        expectedCredentialIssuerWellKnownResponse = getCredentialIssuerWellKnownResponseDto(issuerId,
                Map.of("CredentialType1", getCredentialSupportedResponse("CredentialType1")));
        Mockito.when(issuerWellknownService.getWellknown(credentialIssuerHostUrl))
                .thenReturn(expectedCredentialIssuerWellKnownResponse);

        expectedCredentialIssuerConfigurationResponse = getCredentialIssuerConfigurationResponseDto(issuerId, Map.of("CredentialType1", getCredentialSupportedResponse("CredentialType1")), List.of());
        Mockito.when(authorizationServerService.getWellknown(authServerWellknownUrl)).thenReturn(expectedCredentialIssuerConfigurationResponse.getAuthorizationServerWellKnownResponse());
    }

    @Test
    public void shouldReturnAllIssuersWhenSearchValueIsNull() throws ApiNotAccessibleException, IOException, AuthorizationServerWellknownResponseException, InvalidWellknownResponseException {
        issuers.setIssuers(List.of(getIssuerConfigDTO("Issuer1"), getIssuerConfigDTO("Issuer2")));
        issuersConfigJsonValue = new Gson().toJson(issuers);
        Mockito.when(utilities.getIssuersConfigJsonValue()).thenReturn(issuersConfigJsonValue);
        Mockito.when(objectMapper.readValue(issuersConfigJsonValue, IssuersDTO.class)).thenReturn(issuers);
        IssuersDTO expectedIssuers = new IssuersDTO();
        List<IssuerDTO> issuers = new ArrayList<>(List.of(getIssuerConfigDTO("Issuer1"), getIssuerConfigDTO("Issuer2")));
        expectedIssuers.setIssuers(issuers);

        IssuersDTO allIssuers = issuersService.getIssuers(null);

        assertEquals(expectedIssuers, allIssuers);
    }

    @Test
    public void shouldReturnMatchingIssuersWhenSearchValuePatternMatchesWithIssuerName() throws ApiNotAccessibleException, IOException, AuthorizationServerWellknownResponseException, InvalidWellknownResponseException {
        issuers.setIssuers(List.of(getIssuerConfigDTO("Issuer1"), getIssuerConfigDTO("Issuer2")));
        issuersConfigJsonValue = new Gson().toJson(issuers);
        Mockito.when(utilities.getIssuersConfigJsonValue()).thenReturn(issuersConfigJsonValue);
        Mockito.when(objectMapper.readValue(issuersConfigJsonValue, IssuersDTO.class)).thenReturn(issuers);
        IssuersDTO expectedFilteredIssuers = new IssuersDTO();
        List<IssuerDTO> filteredIssuersList = new ArrayList<>(List.of(getIssuerConfigDTO("Issuer1")));
        expectedFilteredIssuers.setIssuers(filteredIssuersList);

        IssuersDTO filteredIssuers = issuersService.getIssuers("Issuer1");

        assertEquals(expectedFilteredIssuers, filteredIssuers);
    }

    @Test(expected = ApiNotAccessibleException.class)
    public void shouldThrowApiNotAccessibleExceptionWhenIssuersJsonStringIsNullForGettingAllIssuers() throws IOException, ApiNotAccessibleException, AuthorizationServerWellknownResponseException, InvalidWellknownResponseException {
        Mockito.when(utilities.getIssuersConfigJsonValue()).thenReturn(null);

        issuersService.getIssuers(null);
    }

    @Test
    public void shouldReturnIssuerDataAndConfigForTheIssuerIdIfExist() throws ApiNotAccessibleException, IOException, InvalidIssuerIdException, AuthorizationServerWellknownResponseException, InvalidWellknownResponseException {
        IssuerDTO expectedIssuer = getIssuerConfigDTO("Issuer3");

        IssuerDTO issuer = issuersService.getIssuerDetails("Issuer3id");

        assertEquals(expectedIssuer, issuer);
    }

    @Test
    public void shouldReturnIssuerDataAndConfigForAllIssuer() throws ApiNotAccessibleException, IOException, AuthorizationServerWellknownResponseException, InvalidWellknownResponseException {
        IssuersDTO expectedIssuers = new IssuersDTO();
        List<IssuerDTO> issuers = new ArrayList<>(List.of(getIssuerConfigDTO("Issuer3"), getIssuerConfigDTO("Issuer4")));
        expectedIssuers.setIssuers(issuers);

        IssuersDTO issuersDTO = issuersService.getAllIssuers();

        assertEquals(expectedIssuers, issuersDTO);
    }

    @Test(expected = InvalidIssuerIdException.class)
    public void shouldThrowExceptionIfTheIssuerIdNotExists() throws ApiNotAccessibleException, IOException, InvalidIssuerIdException, AuthorizationServerWellknownResponseException, InvalidWellknownResponseException {
        issuersService.getIssuerDetails("Issuer5id");
    }

    @Test(expected = ApiNotAccessibleException.class)
    public void shouldThrowApiNotAccessibleExceptionWhenIssuersJsonStringIsNullForGettingIssuerConfig() throws IOException, ApiNotAccessibleException, InvalidIssuerIdException, AuthorizationServerWellknownResponseException, InvalidWellknownResponseException {
        Mockito.when(utilities.getIssuersConfigJsonValue()).thenReturn(null);

        issuersService.getIssuerDetails("Issuers1id");
    }

    @Test
    public void shouldReturnOnlyEnabledIssuers() throws IOException, ApiNotAccessibleException, AuthorizationServerWellknownResponseException, InvalidWellknownResponseException {
        IssuersDTO issuers = new IssuersDTO();
        IssuerDTO enabledIssuer = getIssuerConfigDTO("Issuer1");
        IssuerDTO disabledIssuer = getIssuerConfigDTO("Issuer2");
        disabledIssuer.setEnabled("false");
        issuers.setIssuers(List.of(enabledIssuer, disabledIssuer));
        Mockito.when(utilities.getIssuersConfigJsonValue()).thenReturn(new Gson().toJson(issuers));
        IssuersDTO expectedIssuersDTO = new IssuersDTO();
        expectedIssuersDTO.setIssuers(List.of(enabledIssuer));

        IssuersDTO actualIssuersDTO = issuersService.getIssuers("");

        assertEquals(expectedIssuersDTO, actualIssuersDTO);
        assertEquals(actualIssuersDTO.getIssuers().get(0).getEnabled(), "true");
        assertEquals(actualIssuersDTO.getIssuers().size(), 1);
    }

    @Test
    public void shouldReturnProperCredentialConfigurationsForTheRequestedIssuer() throws AuthorizationServerWellknownResponseException, ApiNotAccessibleException, IOException, InvalidWellknownResponseException {
        CredentialIssuerConfigurationResponse actualCredentialIssuerConfigurationResponse = issuersService.getIssuerConfiguration("Issuer3id");

        assertEquals(expectedCredentialIssuerConfigurationResponse, actualCredentialIssuerConfigurationResponse);
    }

    @Test
    public void issuersConfigShouldThrowExceptionIfAnyErrorOccurredWhileFetchingIssuersWellknown() throws ApiNotAccessibleException, IOException {
        Mockito.when(utilities.getIssuersConfigJsonValue()).thenReturn(null);

        ApiNotAccessibleException actualException = assertThrows(ApiNotAccessibleException.class, () -> {
            issuersService.getIssuerConfiguration(issuerId);
        });

        assertEquals("RESIDENT-APP-026 --> Api not accessible failure", actualException.getMessage());
        verify(utilities, times(1)).getIssuersConfigJsonValue();
    }


    @Test
    public void issuersConfigShouldThrowExceptionIfAnyErrorOccurredWhileFetchingIssuersAuthorizationServerWellknown() throws IOException, AuthorizationServerWellknownResponseException {
        Mockito.when(authorizationServerService.getWellknown(authServerWellknownUrl)).thenThrow(new AuthorizationServerWellknownResponseException("well-known api is not accessible"));

        AuthorizationServerWellknownResponseException actualException = assertThrows(AuthorizationServerWellknownResponseException.class, () -> {
            issuersService.getIssuerConfiguration("Issuer3id");
        });

        assertEquals("RESIDENT-APP-042 --> Invalid Authorization Server well-known from server:\n" +
                "well-known api is not accessible", actualException.getMessage());
        verify(authorizationServerService, times(1)).getWellknown(authServerWellknownUrl);
    }
}