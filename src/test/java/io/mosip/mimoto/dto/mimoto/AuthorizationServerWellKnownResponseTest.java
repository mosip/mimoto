package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class AuthorizationServerWellKnownResponseTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    public void shouldReadParMetadataWhenPresent() throws Exception {
        String json = """
                {
                  "authorization_endpoint": "https://dev/authorize",
                  "token_endpoint": "https://dev/token",
                  "grant_types_supported": ["authorization_code"],
                  "pushed_authorization_request_endpoint": "https://dev/par",
                  "require_pushed_authorization_requests": true
                }
                """;

        AuthorizationServerWellKnownResponse actual = objectMapper.readValue(json, AuthorizationServerWellKnownResponse.class);

        assertEquals("https://dev/par", actual.getPushedAuthorizationRequestEndpoint());
        assertEquals(Boolean.TRUE, actual.getRequirePushedAuthorizationRequests());
    }

    @Test
    public void shouldLeaveParMetadataNullWhenAbsent() throws Exception {
        String json = """
                {
                  "authorization_endpoint": "https://dev/authorize",
                  "token_endpoint": "https://dev/token",
                  "grant_types_supported": ["authorization_code"]
                }
                """;

        AuthorizationServerWellKnownResponse actual = objectMapper.readValue(json, AuthorizationServerWellKnownResponse.class);
        Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

        assertNull(actual.getPushedAuthorizationRequestEndpoint());
        assertNull(actual.getRequirePushedAuthorizationRequests());
        assertTrue(validator.validate(actual).isEmpty());
    }
}
