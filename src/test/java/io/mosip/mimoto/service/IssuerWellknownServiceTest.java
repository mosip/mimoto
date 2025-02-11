package io.mosip.mimoto.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerConfigurationResponse;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import io.mosip.mimoto.service.impl.IssuerWellknownServiceImpl;
import io.mosip.mimoto.util.CredentialIssuerWellknownResponseValidator;
import io.mosip.mimoto.util.RestApiClient;
import jakarta.validation.Validator;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static io.mosip.mimoto.util.TestUtilities.*;
import static io.mosip.mimoto.util.TestUtilities.getCredentialSupportedResponse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@RunWith(MockitoJUnitRunner.class)
public class IssuerWellknownServiceTest {

    @InjectMocks
    IssuerWellknownServiceImpl issuerWellknownService = new IssuerWellknownServiceImpl();

    @Mock
    Validator validator;

    @Mock
    RestApiClient restApiClient;

    @Mock
    CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator;

    @Mock
    ObjectMapper objectMapper;

    List<String> issuerConfigRelatedFields = List.of("additional_headers", "authorization_endpoint", "authorization_audience", "credential_endpoint", "credential_audience");

    String issuerWellKnownUrl, issuerId, credentialIssuerHostUrl, authServerWellknownUrl;
    CredentialIssuerConfigurationResponse expectedCredentialIssuerConfigurationResponse;

    CredentialIssuerWellKnownResponse expectedCredentialIssuerWellKnownResponse;

    @Before
    public void setUp() throws Exception {
        credentialIssuerHostUrl = "https://issuer.env.net";
        issuerWellKnownUrl = "https://issuer.env.net/.well-known/openid-credential-issuer";
        expectedCredentialIssuerWellKnownResponse = getCredentialIssuerWellKnownResponseDto("Issuer1",
                Map.of("CredentialType1", getCredentialSupportedResponse("CredentialType1")));
        String expectedWellknownJson = getExpectedWellKnownJson();
        Mockito.when(restApiClient.getApi(issuerWellKnownUrl, String.class))
                .thenReturn(expectedWellknownJson);
        Mockito.when(objectMapper.readValue(expectedWellknownJson, CredentialIssuerWellKnownResponse.class)).thenReturn(expectedCredentialIssuerWellKnownResponse);
    }

    @Test
    public void shouldReturnIssuerWellknownForTheRequestedIssuerId() throws ApiNotAccessibleException, IOException, InvalidWellknownResponseException {
        CredentialIssuerWellKnownResponse actualCredentialIssuerWellKnownResponse = issuerWellknownService.getWellknown(credentialIssuerHostUrl);

        assertEquals(expectedCredentialIssuerWellKnownResponse, actualCredentialIssuerWellKnownResponse);
        verify(restApiClient, times(1)).getApi(issuerWellKnownUrl, String.class);
    }

    @Test
    public void shouldThrowExceptionIfAnyIssuerOccurredWhileFetchingIssuerWellknown() throws ApiNotAccessibleException, IOException, InvalidWellknownResponseException {
        Mockito.when(restApiClient.getApi(issuerWellKnownUrl, String.class))
                .thenReturn(null);

        ApiNotAccessibleException actualException = assertThrows(ApiNotAccessibleException.class, () -> {
            issuerWellknownService.getWellknown(credentialIssuerHostUrl);
        });

        assertEquals("RESIDENT-APP-026 --> Api not accessible failure", actualException.getMessage());
        verify(restApiClient, times(1)).getApi(issuerWellKnownUrl, String.class);
    }
}