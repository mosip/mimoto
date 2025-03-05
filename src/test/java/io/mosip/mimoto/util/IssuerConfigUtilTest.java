package io.mosip.mimoto.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.mimoto.AuthorizationServerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.AuthorizationServerWellknownResponseException;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import jakarta.validation.Validator;
import lombok.extern.slf4j.Slf4j;
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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@Slf4j
@RunWith(MockitoJUnitRunner.class)
public class IssuerConfigUtilTest {

    @InjectMocks
    IssuerConfigUtil issuersConfigUtil = new IssuerConfigUtil();

    @Mock
    RestApiClient restApiClient;

    @Mock
    ObjectMapper objectMapper;

    @Mock
    Validator validator;

    @Mock
    CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator;


    String authorizationServerWellknownUrl, authorizationServerHostUrl, issuerWellKnownUrl,exceptionMsgPrefix, issuerId, credentialIssuerHostUrl, authServerWellknownUrl;

    CredentialIssuerWellKnownResponse expectedCredentialIssuerWellKnownResponse;


    @Before
    public void setUp() throws IOException {
        //Auth server wellknown setup
        authorizationServerWellknownUrl = "https://dev/authorize/.well-known/oauth-authorization-server";
        authorizationServerHostUrl = "https://dev/authorize";
        exceptionMsgPrefix = "RESIDENT-APP-042 --> Invalid Authorization Server well-known from server:\n";

        //Issuer wellknown setup
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
    public void shouldThrowExceptionIfResponseIsNullWhenGettingAuthServerWellknownConfig() {
        String expectedExceptionMessage = exceptionMsgPrefix + "java.lang.Exception: well-known api is not accessible";
        Mockito.when(restApiClient.getApi(authorizationServerWellknownUrl, String.class)).thenReturn(null);

        AuthorizationServerWellknownResponseException actualException = assertThrows(AuthorizationServerWellknownResponseException.class, () -> {
            issuersConfigUtil.getAuthServerWellknown(authorizationServerHostUrl);
        });

        assertEquals(expectedExceptionMessage, actualException.getMessage());
    }

    @Test
    public void shouldThrowExceptionIfAuthorizationEndpointIsMissingInAuthServerWellknownResponse() throws Exception {
        String expectedExceptionMessage = exceptionMsgPrefix + "java.lang.Exception: Validation failed:\n" + "authorizationEndpoint: must not be blank";
        AuthorizationServerWellKnownResponse expectedAuthorizationServerWellKnownResponse = getAuthServerWellknownResponseDto(List.of("authorization_endpoint"));
        String expectedIssuersConfigJson = getExpectedIssuersConfigJson();
        Mockito.when(restApiClient.getApi(authorizationServerWellknownUrl, String.class)).thenReturn(expectedIssuersConfigJson);
        Mockito.when(objectMapper.readValue(expectedIssuersConfigJson, AuthorizationServerWellKnownResponse.class)).thenReturn(expectedAuthorizationServerWellKnownResponse);

        AuthorizationServerWellknownResponseException actualException = assertThrows(AuthorizationServerWellknownResponseException.class, () -> {
            issuersConfigUtil.getAuthServerWellknown(authorizationServerHostUrl);
        });

        assertEquals(expectedExceptionMessage, actualException.getMessage());
    }

    @Test
    public void shouldReturnResponseIfTheAuthServerHostUrlAndWellknownResponseAreValid() throws Exception {
        AuthorizationServerWellKnownResponse expectedAuthorizationServerWellKnownResponse = getAuthServerWellknownResponseDto(List.of());
        String expectedIssuersConfigJson = getExpectedIssuersConfigJson();
        Mockito.when(restApiClient.getApi(authorizationServerWellknownUrl, String.class)).thenReturn(expectedIssuersConfigJson);
        Mockito.when(objectMapper.readValue(expectedIssuersConfigJson, AuthorizationServerWellKnownResponse.class)).thenReturn(expectedAuthorizationServerWellKnownResponse);

        AuthorizationServerWellKnownResponse actualAuthorizationServerWellKnownResponse = issuersConfigUtil.getAuthServerWellknown(authorizationServerHostUrl);

        assertEquals(expectedAuthorizationServerWellKnownResponse, actualAuthorizationServerWellKnownResponse);
    }

    @Test
    public void shouldReturnIssuerWellknownForTheRequestedIssuerId() throws ApiNotAccessibleException, IOException, InvalidWellknownResponseException {
        CredentialIssuerWellKnownResponse actualCredentialIssuerWellKnownResponse = issuersConfigUtil.getIssuerWellknown(credentialIssuerHostUrl);

        assertEquals(expectedCredentialIssuerWellKnownResponse, actualCredentialIssuerWellKnownResponse);
        verify(restApiClient, times(1)).getApi(issuerWellKnownUrl, String.class);
    }

    @Test
    public void shouldThrowExceptionIfAnyIssuerOccurredWhileFetchingIssuerWellknown() throws ApiNotAccessibleException, IOException, InvalidWellknownResponseException {
        Mockito.when(restApiClient.getApi(issuerWellKnownUrl, String.class))
                .thenReturn(null);

        ApiNotAccessibleException actualException = assertThrows(ApiNotAccessibleException.class, () -> {
            issuersConfigUtil.getIssuerWellknown(credentialIssuerHostUrl);
        });

        assertEquals("RESIDENT-APP-026 --> Api not accessible failure", actualException.getMessage());
        verify(restApiClient, times(1)).getApi(issuerWellKnownUrl, String.class);
    }

}

