package io.mosip.mimoto.util;

import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;

public class UrlParameterUtils {

    private static final String CLIENT_ID = "client_id";

    private static final String RESPONSE_URI = "response_uri";

    /**
     * Extracts a query parameter value from a URL using Apache URLEncodedUtils
     *
     * @param url           the URL to parse
     * @param parameterName the name of the parameter to extract
     * @return the decoded parameter value, or null if not found
     */
    private static String extractQueryParameter(String url, String parameterName) throws URISyntaxException {
        if (url == null || url.trim().isEmpty()) {
            return null;
        }

        URI uri = new URI(url);
        List<NameValuePair> params = URLEncodedUtils.parse(uri, StandardCharsets.UTF_8);

        for (NameValuePair param : params) {
            if (parameterName.equals(param.getName())) {
                return param.getValue();
            }
        }
        return null;
    }

    public static String extractClientIdFromUrl(String url) throws URISyntaxException {
        return extractQueryParameter(url, CLIENT_ID);
    }

    public static List<String> extractResponseUrisFromUrl(String url) throws URISyntaxException {
        String responseUriValue = extractQueryParameter(url, RESPONSE_URI);
        return responseUriValue != null ? Collections.singletonList(responseUriValue) : Collections.emptyList();
    }
}
