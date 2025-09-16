package io.mosip.mimoto.util;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;

import io.mosip.openID4VP.authorizationRequest.Verifier;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ClientValidationUtils {

    private static final String clientId = "client_id";

    private static final String responseUri = "response_uri";

    private static final int arrayLimit = 2;

    public static boolean isClientValid(List<Verifier> preRegisteredVerifiers,
            String urlEncodedVPAuthorizationRequest) {

        if (urlEncodedVPAuthorizationRequest == null || urlEncodedVPAuthorizationRequest.trim().isEmpty()) {
            log.warn("URL encoded VP authorization request is null or empty");
            return false;
        }

        try {
            String clientId = extractClientIdFromUrl(urlEncodedVPAuthorizationRequest);
            List<String> responseUris = extractResponseUrisFromUrl(urlEncodedVPAuthorizationRequest);

            if (clientId == null || clientId.trim().isEmpty()) {
                log.warn("No client_id found in the authorization request URL");
                return false;
            }

            boolean isValid = preRegisteredVerifiers.stream()
                    .anyMatch(verifier -> clientId.equals(verifier.getClientId())
                            && verifier.getResponseUris().containsAll(responseUris));

            return isValid;

        } catch (Exception e) {
            log.error("Error during client validation for URL: {}", urlEncodedVPAuthorizationRequest, e);
            return false;
        }
    }

    /**
     * Extracts a query parameter value from a URL
     * 
     * @param url           the URL to parse
     * @param parameterName the name of the parameter to extract
     * @return the decoded parameter value, or null if not found
     */
    private static String extractQueryParameter(String url, String parameterName) {
        try {
            int queryIndex = url.indexOf('?');
            if (queryIndex == -1) {
                return null;
            }

            String queryString = url.substring(queryIndex + 1);
            String[] params = queryString.split("&");

            for (String param : params) {
                String[] keyValue = param.split("=", arrayLimit);
                if (keyValue.length == arrayLimit && parameterName.equals(keyValue[0])) {
                    return URLDecoder.decode(keyValue[1], StandardCharsets.UTF_8);
                }
            }
            return null;
        } catch (Exception e) {
            log.error("Error extracting {} from URL: {}", parameterName, url, e);
            return null;
        }
    }

    private static String extractClientIdFromUrl(String url) {
        return extractQueryParameter(url, clientId);
    }

    private static List<String> extractResponseUrisFromUrl(String url) {
        String responseUriValue = extractQueryParameter(url, responseUri);
        return responseUriValue != null ? Collections.singletonList(responseUriValue) : Collections.emptyList();
    }
}
