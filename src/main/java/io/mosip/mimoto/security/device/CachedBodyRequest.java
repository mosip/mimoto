package io.mosip.mimoto.security.device;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import org.springframework.http.MediaType;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Reads the request body once so it can be hashed for the device proof and still be read by the controller.
 * Form parameters are parsed from the cached body because the container can no longer read them from the stream.
 */
class CachedBodyRequest extends HttpServletRequestWrapper {

    private final byte[] body;
    private final Map<String, String[]> parameters;

    CachedBodyRequest(HttpServletRequest request, int maxBodyBytes) throws IOException {
        super(request);
        byte[] read = request.getInputStream().readNBytes(maxBodyBytes + 1);
        if (read.length > maxBodyBytes) {
            throw new IOException("Request body exceeds " + maxBodyBytes + " bytes");
        }
        this.body = read;
        this.parameters = Collections.unmodifiableMap(parseParameters(request));
    }

    byte[] body() {
        return body;
    }

    private Map<String, String[]> parseParameters(HttpServletRequest request) {
        Map<String, List<String>> values = new LinkedHashMap<>();
        Charset charset = charset(request);
        addPairs(values, request.getQueryString(), StandardCharsets.UTF_8);
        if (isForm(request)) {
            addPairs(values, new String(body, charset), charset);
        }
        Map<String, String[]> result = new LinkedHashMap<>();
        values.forEach((k, v) -> result.put(k, v.toArray(String[]::new)));
        return result;
    }

    private static void addPairs(Map<String, List<String>> values, String encoded, Charset charset) {
        if (encoded == null || encoded.isEmpty()) {
            return;
        }
        for (String pair : encoded.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int eq = pair.indexOf('=');
            String name = URLDecoder.decode(eq < 0 ? pair : pair.substring(0, eq), charset);
            String value = eq < 0 ? "" : URLDecoder.decode(pair.substring(eq + 1), charset);
            values.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
        }
    }

    private static boolean isForm(HttpServletRequest request) {
        String contentType = request.getContentType();
        if (contentType == null) {
            return false;
        }
        try {
            return MediaType.APPLICATION_FORM_URLENCODED.includes(MediaType.parseMediaType(contentType));
        } catch (Exception e) {
            return false;
        }
    }

    private static Charset charset(HttpServletRequest request) {
        try {
            return request.getCharacterEncoding() == null ? StandardCharsets.UTF_8 : Charset.forName(request.getCharacterEncoding());
        } catch (Exception e) {
            return StandardCharsets.UTF_8;
        }
    }

    @Override
    public ServletInputStream getInputStream() {
        ByteArrayInputStream in = new ByteArrayInputStream(body);
        return new ServletInputStream() {
            @Override
            public boolean isFinished() {
                return in.available() == 0;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener listener) {
                throw new UnsupportedOperationException();
            }

            @Override
            public int read() {
                return in.read();
            }
        };
    }

    @Override
    public BufferedReader getReader() {
        return new BufferedReader(new InputStreamReader(new ByteArrayInputStream(body), charset((HttpServletRequest) getRequest())));
    }

    @Override
    public String getParameter(String name) {
        String[] v = parameters.get(name);
        return v == null || v.length == 0 ? null : v[0];
    }

    @Override
    public Map<String, String[]> getParameterMap() {
        return parameters;
    }

    @Override
    public Enumeration<String> getParameterNames() {
        return Collections.enumeration(parameters.keySet());
    }

    @Override
    public String[] getParameterValues(String name) {
        return parameters.get(name);
    }
}
