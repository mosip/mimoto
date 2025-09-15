package io.mosip.mimoto.util;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import io.mosip.openID4VP.authorizationRequest.Verifier;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ClientValidationUtils {
    public static boolean isClientValid(List<Verifier> preRegisteredVerifiers,
            String urlEncodedVPAuthorizationRequest) {
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

            log.info(
                    "Client validation result for client_id: {} (decoded: {}) and response_uris: {} (decoded: {}) is: {}",
                    clientId, clientId, responseUris, responseUris, isValid);
            return isValid;

        } catch (Exception e) {
            return false;
        }
    }

    private static String extractClientIdFromUrl(String url) {
        try {
            int queryIndex = url.indexOf('?');
            if (queryIndex == -1) {
                return null;
            }

            String queryString = url.substring(queryIndex + 1);
            String[] params = queryString.split("&");

            for (String param : params) {
                String[] keyValue = param.split("=", 2);
                if (keyValue.length == 2 && "client_id".equals(keyValue[0])) {
                    return URLDecoder.decode(keyValue[1], StandardCharsets.UTF_8);
                }
            }

            return null;
        } catch (Exception e) {
            log.error("Error extracting client_id from URL: {}", url, e);
            return null;
        }
    }

    private static List<String> extractResponseUrisFromUrl(String url) {
        try {
            int queryIndex = url.indexOf('?');
            if (queryIndex == -1) {
                return Collections.emptyList();
            }

            String queryString = url.substring(queryIndex + 1);
            String[] params = queryString.split("&");

            for (String param : params) {
                String[] keyValue = param.split("=", 2);
                if (keyValue.length == 2 && "response_uri".equals(keyValue[0])) {
                    String responseUriValue = keyValue[1];
                    responseUriValue = URLDecoder.decode(responseUriValue, StandardCharsets.UTF_8);
                    String[] responseUris = responseUriValue.split(",");
                    return Arrays.asList(responseUris);
                }
            }

            return Collections.emptyList();
        } catch (Exception e) {
            log.error("Error extracting response_uri from URL: {}", url, e);
            return Collections.emptyList();
        }
    }
}
