package io.mosip.mimoto.util;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class AuthorizationUrlBuilderTest {

    @Test
    public void shouldBuildAuthorizationUrlWithOnlyClientIdAndRequestUri() {
        String url = AuthorizationUrlBuilder.buildParAuthorizationUrl(
                "https://dev/authorize", "client-1", "urn:example:request");

        assertEquals("https://dev/authorize?client_id=client-1&request_uri=urn%3Aexample%3Arequest", url);
    }

    @Test
    public void shouldAppendRequestUriWhenAuthorizationEndpointAlreadyHasQuery() {
        String url = AuthorizationUrlBuilder.buildParAuthorizationUrl(
                "https://dev/authorize?foo=bar", "client-1", "urn:example:request");

        assertEquals("https://dev/authorize?foo=bar&client_id=client-1&request_uri=urn%3Aexample%3Arequest", url);
    }

    @Test
    public void shouldRejectBlankRequestUri() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> AuthorizationUrlBuilder.buildParAuthorizationUrl("https://dev/authorize", "client-1", " "));

        assertEquals("request_uri cannot be blank", exception.getMessage());
    }
}
