package io.mosip.mimoto.util;

import io.mosip.openID4VP.authorizationRequest.Verifier;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

@Slf4j
public class ClientValidationUtils {

    private static final String CLIENT_ID = "client_id";

    private static final String RESPONSE_URI = "response_uri";

    public static boolean isVerifierClientPreregistered(List<Verifier> preRegisteredVerifiers, String urlEncodedVPAuthorizationRequest) {

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

            return preRegisteredVerifiers.stream().anyMatch(verifier -> clientId.equals(verifier.getClientId()) && new HashSet<>(verifier.getResponseUris()).containsAll(responseUris));

        } catch (Exception e) {
            log.error("Error during client validation for URL: {}", urlEncodedVPAuthorizationRequest, e);
            return false;
        }
    }

    /**
     * Extracts a query parameter value from a URL using Apache URLEncodedUtils
     *
     * @param url           the URL to parse
     * @param parameterName the name of the parameter to extract
     * @return the decoded parameter value, or null if not found
     */
    private static String extractQueryParameter(String url, String parameterName) {
        try {
            URI uri = new URI(url);
            List<NameValuePair> params = URLEncodedUtils.parse(uri, StandardCharsets.UTF_8);

            for (NameValuePair param : params) {
                if (parameterName.equals(param.getName())) {
                    return param.getValue();
                }
            }
            return null;
        } catch (URISyntaxException e) {
            log.error("Invalid URL syntax: {}", url, e);
            return null;
        } catch (Exception e) {
            log.error("Error extracting {} from URL: {}", parameterName, url, e);
            return null;
        }
    }

    private static String extractClientIdFromUrl(String url) {
        return extractQueryParameter(url, CLIENT_ID);
    }

    private static List<String> extractResponseUrisFromUrl(String url) {
        String responseUriValue = extractQueryParameter(url, RESPONSE_URI);
        return responseUriValue != null ? Collections.singletonList(responseUriValue) : Collections.emptyList();
    }
}
