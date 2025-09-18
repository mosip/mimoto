package io.mosip.mimoto.util;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class UrlParameterUtilsTest {

    private static final String VALID_CLIENT_ID = "https://injiverify.collab.mosip.net";
    private static final String ENCODED_CLIENT_ID = "https%3A%2F%2Finjiverify.collab.mosip.net";
    private static final String VALID_RESPONSE_URI = "https://example.com/callback";
    private static final String ENCODED_RESPONSE_URI = "https%3A%2F%2Fexample.com%2Fcallback";

    /**
     * Helper method to safely invoke methods and cast results without unchecked
     * warnings
     */
    @SuppressWarnings("unchecked")
    private static <T> T invokeMethod(Class<?> clazz, String methodName, Class<?>[] paramTypes, Object... args) throws Exception {
        Method method = clazz.getMethod(methodName, paramTypes);
        method.setAccessible(true);
        return (T) method.invoke(null, args);
    }

    @Test
    public void testExtractClientIdFromUrlWithValidClientId() throws Exception {
        String url = "https://example.com?client_id=" + ENCODED_CLIENT_ID + "&other_param=value";

        String result = invokeMethod(UrlParameterUtils.class, "extractClientIdFromUrl", new Class[]{String.class}, url);

        assertEquals(VALID_CLIENT_ID, result);
    }

    @Test
    public void testExtractClientIdFromUrlWithNoQueryParameters() throws Exception {
        String url = "https://example.com";

        String result = invokeMethod(UrlParameterUtils.class, "extractClientIdFromUrl", new Class[]{String.class}, url);

        assertNull(result);
    }

    @Test
    public void testExtractClientIdFromUrlWithNoClientIdParameter() throws Exception {
        String url = "https://example.com?other_param=value&another_param=value2";

        String result = invokeMethod(UrlParameterUtils.class, "extractClientIdFromUrl", new Class[]{String.class}, url);

        assertNull(result);
    }

    @Test
    public void testExtractClientIdFromUrlWithMalformedParameter() throws Exception {
        String url = "https://example.com?client_id&other_param=value";

        String result = invokeMethod(UrlParameterUtils.class, "extractClientIdFromUrl", new Class[]{String.class}, url);

        assertNull(result);
    }

    @Test
    public void testExtractClientIdFromUrlWithNullInput() throws Exception {
        String url = null;

        String result = invokeMethod(UrlParameterUtils.class, "extractClientIdFromUrl", new Class[]{String.class}, url);

        assertNull(result);
    }

    @Test
    public void testExtractClientIdFromUrlWithEmptyValue() throws Exception {
        String url = "https://example.com?client_id=&other_param=value";

        String result = invokeMethod(UrlParameterUtils.class, "extractClientIdFromUrl", new Class[]{String.class}, url);

        assertEquals("", result);
    }

    @Test
    public void testExtractResponseUrisFromUrlWithValidResponseUri() throws Exception {
        String url = "https://example.com?response_uri=" + ENCODED_RESPONSE_URI + "&other_param=value";

        List<String> result = invokeMethod(UrlParameterUtils.class, "extractResponseUrisFromUrl", new Class[]{String.class}, url);

        assertEquals(1, result.size());
        assertEquals(VALID_RESPONSE_URI, result.get(0));
    }

    @Test
    public void testExtractResponseUrisFromUrlWithNoQueryParameters() throws Exception {
        String url = "https://example.com";

        List<String> result = invokeMethod(UrlParameterUtils.class, "extractResponseUrisFromUrl", new Class[]{String.class}, url);

        assertTrue(result.isEmpty());
    }

    @Test
    public void testExtractResponseUrisFromUrlWithNoResponseUriParameter() throws Exception {
        String url = "https://example.com?other_param=value&another_param=value2";

        List<String> result = invokeMethod(UrlParameterUtils.class, "extractResponseUrisFromUrl", new Class[]{String.class}, url);

        assertTrue(result.isEmpty());
    }

    @Test
    public void testExtractResponseUrisFromUrlWithMalformedParameter() throws Exception {
        String url = "https://example.com?response_uri&other_param=value";

        List<String> result = invokeMethod(UrlParameterUtils.class, "extractResponseUrisFromUrl", new Class[]{String.class}, url);

        assertTrue(result.isEmpty());
    }

    @Test
    public void testExtractResponseUrisFromUrlWithNullInput() throws Exception {
        String url = null;

        List<String> result = invokeMethod(UrlParameterUtils.class, "extractResponseUrisFromUrl", new Class[]{String.class}, url);

        assertTrue(result.isEmpty());
    }

    @Test
    public void testExtractResponseUrisFromUrlWithEmptyValue() throws Exception {
        String url = "https://example.com?response_uri=&other_param=value";

        List<String> result = invokeMethod(UrlParameterUtils.class, "extractResponseUrisFromUrl", new Class[]{String.class}, url);

        assertEquals(1, result.size());
        assertEquals("", result.get(0));
    }

    @Test
    public void testExtractResponseUrisFromUrlWithCommaOnly() throws Exception {
        String url = "https://example.com?response_uri=,"; // Direct comma

        List<String> result = invokeMethod(UrlParameterUtils.class, "extractResponseUrisFromUrl", new Class[]{String.class}, url);

        assertEquals(1, result.size());
        assertEquals(",", result.get(0));
    }

    @Test
    public void testExtractResponseUrisFromUrlWithMultipleCommas() throws Exception {
        String url = "https://example.com?response_uri=uri1,uri2,uri3";

        List<String> result = invokeMethod(UrlParameterUtils.class, "extractResponseUrisFromUrl", new Class[]{String.class}, url);

        assertEquals(1, result.size());
        assertEquals("uri1,uri2,uri3", result.get(0));
    }

    @Test
    public void testExtractClientIdFromUrlWithSpecialCharacters() throws Exception {
        String specialClientId = "client-id_with.special+chars";
        String encodedClientId = "client-id_with.special%2Bchars";
        String url = "https://example.com?client_id=" + encodedClientId + "&other_param=value";

        String result = invokeMethod(UrlParameterUtils.class, "extractClientIdFromUrl", new Class[]{String.class}, url);

        assertEquals(specialClientId, result);
    }

    @Test
    public void testExtractResponseUrisFromUrlWithSpecialCharacters() throws Exception {
        String specialUri = "https://example.com/callback?param=value&other=test";
        String encodedUri = "https%3A%2F%2Fexample.com%2Fcallback%3Fparam%3Dvalue%26other%3Dtest";
        String url = "https://example.com?response_uri=" + encodedUri + "&other_param=value";

        List<String> result = invokeMethod(UrlParameterUtils.class, "extractResponseUrisFromUrl", new Class[]{String.class}, url);

        assertEquals(1, result.size());
        assertEquals(specialUri, result.get(0));
    }

    @Test
    public void testExtractClientIdFromUrlWithEmptyString() throws Exception {
        String url = "https://example.com?client_id=&other_param=value";

        String result = invokeMethod(UrlParameterUtils.class, "extractClientIdFromUrl", new Class[]{String.class}, url);

        assertEquals("", result);
    }

    @Test
    public void testExtractResponseUrisFromUrlWithEmptyString() throws Exception {
        String url = "https://example.com?response_uri=&other_param=value";

        List<String> result = invokeMethod(UrlParameterUtils.class, "extractResponseUrisFromUrl", new Class[]{String.class}, url);

        assertEquals(1, result.size());
        assertEquals("", result.get(0));
    }

    @Test
    public void testExtractClientIdFromUrlWithWhitespace() throws Exception {
        String url = "https://example.com?client_id=%20&other_param=value";

        String result = invokeMethod(UrlParameterUtils.class, "extractClientIdFromUrl", new Class[]{String.class}, url);

        assertEquals(" ", result);
    }

    @Test
    public void testExtractResponseUrisFromUrlWithWhitespace() throws Exception {
        String url = "https://example.com?response_uri=%20&other_param=value";

        List<String> result = invokeMethod(UrlParameterUtils.class, "extractResponseUrisFromUrl", new Class[]{String.class}, url);

        assertEquals(1, result.size());
        assertEquals(" ", result.get(0));
    }

}
