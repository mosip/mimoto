package io.mosip.mimoto.util;

import org.apache.commons.lang3.StringUtils;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Builds the OpenID4VCI authorization request URL.
 */
public final class AuthorizationUrlBuilder {

    private AuthorizationUrlBuilder() {
    }

    /**
     * Authorization URL used when PAR is not used. The query string carries the authorization parameters, including scope, PKCE, and dpop_jkt.
     */
    public static String buildAuthorizationUrl(String authorizationEndpoint,
                               String clientId,
                               String redirectUri,
                               String scope,
                               String responseType,
                               String state,
                               String codeChallenge,
                               String codeChallengeMethod,
                               String uiLocales,
                               String dPoPJkt) {
        if (StringUtils.isBlank(authorizationEndpoint)) {
            throw new IllegalArgumentException("authorization_endpoint cannot be blank");
        }
        StringBuilder url = new StringBuilder(authorizationEndpoint);
        url.append(authorizationEndpoint.contains("?") ? "&" : "?");
        url.append("client_id=").append(encode(clientId));
        url.append("&redirect_uri=").append(encode(redirectUri));
        url.append("&response_type=").append(encode(responseType));
        url.append("&scope=").append(encode(scope));
        url.append("&state=").append(encode(state));
        url.append("&code_challenge=").append(encode(codeChallenge));
        url.append("&code_challenge_method=").append(encode(codeChallengeMethod));
        if (StringUtils.isNotBlank(uiLocales)) {
            url.append("&ui_locales=").append(encode(uiLocales));
        }
        if (StringUtils.isNotBlank(dPoPJkt)) {
            url.append("&dpop_jkt=").append(encode(dPoPJkt));
        }
        return url.toString();
    }

    /**
     * Authorization URL used after a successful PAR call. The query string carries only client_id and request_uri.
     */
    public static String buildParAuthorizationUrl(String authorizationEndpoint, String clientId, String requestUri) {
        if (StringUtils.isBlank(authorizationEndpoint)) {
            throw new IllegalArgumentException("authorization_endpoint cannot be blank");
        }
        if (StringUtils.isBlank(clientId)) {
            throw new IllegalArgumentException("client_id cannot be blank");
        }
        if (StringUtils.isBlank(requestUri)) {
            throw new IllegalArgumentException("request_uri cannot be blank");
        }
        StringBuilder url = new StringBuilder(authorizationEndpoint);
        url.append(authorizationEndpoint.contains("?") ? "&" : "?");
        url.append("client_id=").append(encode(clientId));
        url.append("&request_uri=").append(encode(requestUri));
        return url.toString();
    }

    private static String encode(String value) {
        return URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8);
    }
}
