package io.mosip.mimoto.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.mimoto.AuthorizationServerWellKnownResponse;
import io.mosip.mimoto.exception.AuthorizationServerWellknownResponseException;
import io.mosip.mimoto.service.impl.AuthorizationServerServiceImpl;
import io.mosip.mimoto.util.RestApiClient;
import lombok.extern.slf4j.Slf4j;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;
import java.net.URI;
import java.util.List;
import static io.mosip.mimoto.util.TestUtilities.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

@Slf4j
@RunWith(MockitoJUnitRunner.class)
public class AuthorizationServerServiceTest {

    @InjectMocks
    AuthorizationServerServiceImpl authorizationServerService = new AuthorizationServerServiceImpl();

    @Mock
    RestApiClient restApiClient;

    @Mock
    ObjectMapper objectMapper;

    String authorizationServerWellknownUrl;

    String authorizationServerHostUrl;

    String exceptionMsgPrefix;

    @Before
    public void setUp() {
        authorizationServerWellknownUrl = "https://dev/authorize/.well-known/oauth-authorization-server";
        authorizationServerHostUrl = "https://dev/authorize";
        exceptionMsgPrefix = "RESIDENT-APP-042 --> Invalid Authorization Server well-known from server:\n";
    }

    @Test
    public void shouldThrowExceptionIfResponseIsNullWhenGettingAuthServerWellknownConfig() throws Exception {
        String expectedExceptionMessage = exceptionMsgPrefix + "java.lang.Exception: well-known api is not accessible";
        Mockito.when(restApiClient.getApi(authorizationServerWellknownUrl, String.class)).thenReturn(null);

        AuthorizationServerWellknownResponseException actualException = assertThrows(AuthorizationServerWellknownResponseException.class, () -> {
            authorizationServerService.getWellknown(authorizationServerHostUrl);
        });

        assertEquals(expectedExceptionMessage, actualException.getMessage());
    }
    
    @Test
    public void shouldThrowExceptionIfAuthorizationEndpointIsMissingInAuthServerWellknownResponse() throws Exception {
        String expectedExceptionMessage = exceptionMsgPrefix + "java.lang.Exception: java.lang.Exception: Validation failed:\n" + "authorizationEndpoint: must not be blank";
        AuthorizationServerWellKnownResponse expectedAuthorizationServerWellKnownResponse = getAuthServerWellknownResponseDto(List.of("authorization_endpoint"));
        String expectedIssuersConfigJson = getExpectedIssuersConfigJson();
        Mockito.when(restApiClient.getApi(authorizationServerWellknownUrl, String.class)).thenReturn(expectedIssuersConfigJson);
        Mockito.when(objectMapper.readValue(expectedIssuersConfigJson, AuthorizationServerWellKnownResponse.class)).thenReturn(expectedAuthorizationServerWellKnownResponse);

        AuthorizationServerWellknownResponseException actualException = assertThrows(AuthorizationServerWellknownResponseException.class, () -> {
            authorizationServerService.getWellknown(authorizationServerHostUrl);
        });

        assertEquals(expectedExceptionMessage, actualException.getMessage());
    }

    @Test
    public void shouldReturnResponseIfTheAuthServerHostUrlAndResponseAreValid() throws Exception {
        AuthorizationServerWellKnownResponse expectedAuthorizationServerWellKnownResponse = getAuthServerWellknownResponseDto(List.of());
        String expectedIssuersConfigJson = getExpectedIssuersConfigJson();
        Mockito.when(restApiClient.getApi(authorizationServerWellknownUrl, String.class)).thenReturn(expectedIssuersConfigJson);
        Mockito.when(objectMapper.readValue(expectedIssuersConfigJson, AuthorizationServerWellKnownResponse.class)).thenReturn(expectedAuthorizationServerWellKnownResponse);

        AuthorizationServerWellKnownResponse actualAuthorizationServerWellKnownResponse = authorizationServerService.getWellknown(authorizationServerHostUrl);

        assertEquals(expectedAuthorizationServerWellKnownResponse, actualAuthorizationServerWellKnownResponse);
    }
}

