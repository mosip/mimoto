package io.mosip.mimoto.service;

import com.google.gson.Gson;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.InvalidIssuerIdException;
import io.mosip.mimoto.service.impl.CredentialServiceImpl;
import io.mosip.mimoto.service.impl.IssuersServiceImpl;
import io.mosip.mimoto.util.RestApiClient;
import io.mosip.mimoto.util.Utilities;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static io.mosip.mimoto.util.TestUtilities.*;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@RunWith(MockitoJUnitRunner.class)
public class IssuersServiceTest {

    @InjectMocks
    IssuersServiceImpl issuersService = new IssuersServiceImpl();

    @InjectMocks
    CredentialServiceImpl credentialService = new CredentialServiceImpl();

    @Mock
    RestApiClient restApiClient;

    @Mock
    Utilities utilities;

    List<String> issuerConfigRelatedFields = List.of("additional_headers", "authorization_endpoint","authorization_audience", "token_endpoint", "proxy_token_endpoint", "credential_endpoint", "credential_audience", "redirect_uri");


    @Before
    public void setUp() throws Exception {
        IssuersDTO issuers = new IssuersDTO();
        issuers.setIssuers(List.of(getIssuerConfigDTO("Issuer1", Collections.emptyList()), getIssuerConfigDTO("Issuer2", Collections.emptyList())));
        Mockito.when(utilities.getIssuersConfigJsonValue()).thenReturn(new Gson().toJson(issuers));
    }

    @Test
    public void shouldReturnIssuersWithIssuerConfigAsNull() throws ApiNotAccessibleException, IOException {
        IssuersDTO expectedIssuers = new IssuersDTO();
        List<IssuerDTO> issuers = new ArrayList<>(List.of(getIssuerConfigDTO("Issuer1", issuerConfigRelatedFields), getIssuerConfigDTO("Issuer2", issuerConfigRelatedFields)));
        expectedIssuers.setIssuers(issuers);

        IssuersDTO expectedFilteredIssuers = new IssuersDTO();
        List<IssuerDTO> filteredIssuersList = new ArrayList<>(List.of(getIssuerConfigDTO("Issuer1", issuerConfigRelatedFields)));
        expectedFilteredIssuers.setIssuers(filteredIssuersList);

        IssuersDTO allIssuers = issuersService.getAllIssuers(null);
        IssuersDTO filteredIssuers = issuersService.getAllIssuers("Issuer1");
        assertEquals(expectedIssuers, allIssuers);
        assertEquals(expectedFilteredIssuers, filteredIssuers);
    }

    @Test(expected = ApiNotAccessibleException.class)
    public void shouldThrowApiNotAccessibleExceptionWhenIssuersJsonStringIsNullForGettingAllIssuers() throws IOException, ApiNotAccessibleException {
        Mockito.when(utilities.getIssuersConfigJsonValue()).thenReturn(null);

        issuersService.getAllIssuers(null);
    }

    @Test
    public void shouldReturnIssuerDataAndConfigForTheIssuerIdIfExist() throws ApiNotAccessibleException, IOException, InvalidIssuerIdException {
        IssuerDTO expectedIssuer = getIssuerConfigDTO("Issuer1", issuerConfigRelatedFields);

        IssuerDTO issuer = issuersService.getIssuerConfig("Issuer1id");

        assertEquals(expectedIssuer, issuer);
    }

    @Test
    public void shouldReturnIssuerWellknownForTheIssuerIdIfExist() throws ApiNotAccessibleException, IOException {
        String issuerId = "Issuer1id";
        String wellKnownUrl = "/.well-known";
        CredentialIssuerWellKnownResponse expextedCredentialIssuerWellKnownResponse=getCredentialIssuerWellKnownResponseDto("Issuer1",
               Map.of("CredentialType1",getCredentialSupportedResponse("CredentialType1")));

        Mockito.when(restApiClient.getApi(wellKnownUrl , String.class))
                .thenReturn(getExpectedWellKnownJson());

        CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse=issuersService.getIssuerWellknown(issuerId);
        assertEquals(expextedCredentialIssuerWellKnownResponse,credentialIssuerWellKnownResponse);
        verify(restApiClient, times(1)).getApi(wellKnownUrl, String.class);
    }

    @Test
    public void shouldReturnIssuerDataAndConfigForAllIssuer() throws ApiNotAccessibleException, IOException {
        IssuersDTO expectedIssuers = new IssuersDTO();
        List<IssuerDTO> issuers = new ArrayList<>(List.of(getIssuerConfigDTO("Issuer1", new ArrayList<>()), getIssuerConfigDTO("Issuer2", new ArrayList<>())));
        expectedIssuers.setIssuers(issuers);

        IssuersDTO issuersDTO = issuersService.getAllIssuersWithAllFields();

        assertEquals(expectedIssuers, issuersDTO);
    }

    @Test(expected = InvalidIssuerIdException.class)
    public void shouldThrowExceptionIfTheIssuerIdNotExists() throws ApiNotAccessibleException, IOException, InvalidIssuerIdException {
        IssuerDTO issuer = issuersService.getIssuerConfig("Issuer3id");
    }

    @Test(expected = ApiNotAccessibleException.class)
    public void shouldThrowApiNotAccessibleExceptionWhenIssuersJsonStringIsNullForGettingIssuerConfig() throws IOException, ApiNotAccessibleException, InvalidIssuerIdException {
        Mockito.when(utilities.getIssuersConfigJsonValue()).thenReturn(null);

        issuersService.getIssuerConfig("Issuers1id");
    }
    @Test
    public void shouldReturnOnlyEnabledIssuers() throws IOException, ApiNotAccessibleException {
        IssuersDTO issuers = new IssuersDTO();
        IssuerDTO enabledIssuer = getIssuerConfigDTO("Issuer1", Collections.emptyList());
        IssuerDTO disbaledIssuer = getIssuerConfigDTO("Issuer2", Collections.emptyList());
        disbaledIssuer.setEnabled("false");
        issuers.setIssuers(List.of(enabledIssuer, disbaledIssuer));
        Mockito.when(utilities.getIssuersConfigJsonValue()).thenReturn(new Gson().toJson(issuers));

        IssuersDTO expectedIssuersDTO = new IssuersDTO();
        expectedIssuersDTO.setIssuers(List.of(enabledIssuer));

        IssuersDTO actualIssuersDTO = issuersService.getAllIssuers("");
        assertEquals(expectedIssuersDTO, actualIssuersDTO);
        assertEquals(actualIssuersDTO.getIssuers().get(0).getEnabled(), "true");
        assertEquals(actualIssuersDTO.getIssuers().size(), 1);
    }
}
