package io.mosip.mimoto.util;

import io.mosip.openID4VP.authorizationRequest.Verifier;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class ClientValidationsUtilsTest {

    private static final String VALID_CLIENT_ID = "https://injiverify.collab.mosip.net";
    private static final String ENCODED_CLIENT_ID = "https%3A%2F%2Finjiverify.collab.mosip.net";
    private static final String VALID_RESPONSE_URI = "https://example.com/callback";
    private static final String ENCODED_RESPONSE_URI = "https%3A%2F%2Fexample.com%2Fcallback";


    @Test
    public void testIsClientValidWithValidClientIdAndMatchingVerifier() {
        List<Verifier> verifiers = List.of(new Verifier(VALID_CLIENT_ID, List.of(VALID_RESPONSE_URI), null));
        String url = "https://example.com?client_id=" + ENCODED_CLIENT_ID + "&response_uri=" + ENCODED_RESPONSE_URI;

        boolean result = ClientValidationUtils.isVerifierClientPreregistered(verifiers, url);

        assertTrue(result);
    }

    @Test
    public void testIsClientValidWithValidClientIdButNoMatchingVerifier() {
        List<Verifier> verifiers = List.of(new Verifier("https://other-verifier.com", List.of(VALID_RESPONSE_URI), null));
        String url = "https://example.com?client_id=" + ENCODED_CLIENT_ID;

        boolean result = ClientValidationUtils.isVerifierClientPreregistered(verifiers, url);

        assertFalse(result);
    }

    @Test
    public void testIsClientValidWithNullClientId() {
        List<Verifier> verifiers = List.of(new Verifier(VALID_CLIENT_ID, List.of(VALID_RESPONSE_URI), null));
        String url = "https://example.com?other_param=value";

        boolean result = ClientValidationUtils.isVerifierClientPreregistered(verifiers, url);

        assertFalse(result);
    }

    @Test
    public void testIsClientValidWithEmptyClientId() {
        List<Verifier> verifiers = List.of(new Verifier(VALID_CLIENT_ID, List.of(VALID_RESPONSE_URI), null));
        String url = "https://example.com?client_id=";

        boolean result = ClientValidationUtils.isVerifierClientPreregistered(verifiers, url);

        assertFalse(result);
    }

    @Test
    public void testIsClientValidWithWhitespaceOnlyClientId() {
        List<Verifier> verifiers = List.of(new Verifier(VALID_CLIENT_ID, List.of(VALID_RESPONSE_URI), null));
        String url = "https://example.com?client_id=%20%20";

        boolean result = ClientValidationUtils.isVerifierClientPreregistered(verifiers, url);

        assertFalse(result);
    }

    @Test
    public void testIsClientValidWithEmptyVerifiersList() {
        List<Verifier> verifiers = Collections.emptyList();
        String url = "https://example.com?client_id=" + ENCODED_CLIENT_ID;

        boolean result = ClientValidationUtils.isVerifierClientPreregistered(verifiers, url);

        assertFalse(result);
    }


    @Test
    public void testIsClientValidWithPartialResponseUrisMatch() {
        List<String> verifierResponseUris = Arrays.asList("https://example.com/callback1", "https://example.com/callback2");
        List<Verifier> verifiers = List.of(new Verifier(VALID_CLIENT_ID, verifierResponseUris, null));
        String url = "https://example.com?client_id=" + ENCODED_CLIENT_ID + "&response_uri=" + ENCODED_RESPONSE_URI;

        boolean result = ClientValidationUtils.isVerifierClientPreregistered(verifiers, url);

        assertFalse(result);
    }

    @Test
    public void testIsClientValidWithExceptionInExtraction() {
        List<Verifier> verifiers = List.of(new Verifier(VALID_CLIENT_ID, List.of(VALID_RESPONSE_URI), null));
        String url = null;

        boolean result = ClientValidationUtils.isVerifierClientPreregistered(verifiers, url);

        assertFalse(result);
    }

    @Test
    public void testExtractClientIdFromUrlWithValidClientId() throws Exception {
        String url = "https://example.com?client_id=" + ENCODED_CLIENT_ID + "&other_param=value";

        Method method = ClientValidationUtils.class.getDeclaredMethod("extractClientIdFromUrl", String.class);
        method.setAccessible(true);
        String result = (String) method.invoke(null, url);

        assertEquals(VALID_CLIENT_ID, result);
    }

    @Test
    public void testExtractClientIdFromUrlWithNoQueryParameters() throws Exception {
        String url = "https://example.com";

        Method method = ClientValidationUtils.class.getDeclaredMethod("extractClientIdFromUrl", String.class);
        method.setAccessible(true);
        String result = (String) method.invoke(null, url);

        assertNull(result);
    }

    @Test
    public void testExtractClientIdFromUrlWithNoClientIdParameter() throws Exception {
        String url = "https://example.com?other_param=value&another_param=value2";

        Method method = ClientValidationUtils.class.getDeclaredMethod("extractClientIdFromUrl", String.class);
        method.setAccessible(true);
        String result = (String) method.invoke(null, url);

        assertNull(result);
    }

    @Test
    public void testExtractClientIdFromUrlWithMalformedParameter() throws Exception {
        String url = "https://example.com?client_id&other_param=value";

        Method method = ClientValidationUtils.class.getDeclaredMethod("extractClientIdFromUrl", String.class);
        method.setAccessible(true);
        String result = (String) method.invoke(null, url);

        assertNull(result);
    }

    @Test
    public void testExtractClientIdFromUrlWithException() throws Exception {
        String url = null;

        Method method = ClientValidationUtils.class.getDeclaredMethod("extractClientIdFromUrl", String.class);
        method.setAccessible(true);
        String result = (String) method.invoke(null, url);

        assertNull(result);
    }

    @Test
    public void testExtractClientIdFromUrlWithEmptyValue() throws Exception {
        String url = "https://example.com?client_id=&other_param=value";

        Method method = ClientValidationUtils.class.getDeclaredMethod("extractClientIdFromUrl", String.class);
        method.setAccessible(true);
        String result = (String) method.invoke(null, url);

        assertEquals("", result);
    }

    @Test
    public void testExtractResponseUrisFromUrlWithValidResponseUri() throws Exception {
        String url = "https://example.com?response_uri=" + ENCODED_RESPONSE_URI + "&other_param=value";

        Method method = ClientValidationUtils.class.getDeclaredMethod("extractResponseUrisFromUrl", String.class);
        method.setAccessible(true);
        @SuppressWarnings("unchecked") List<String> result = (List<String>) method.invoke(null, url);

        assertEquals(1, result.size());
        assertEquals(VALID_RESPONSE_URI, result.get(0));
    }

    @Test
    public void testExtractResponseUrisFromUrlWithNoQueryParameters() throws Exception {
        String url = "https://example.com";

        Method method = ClientValidationUtils.class.getDeclaredMethod("extractResponseUrisFromUrl", String.class);
        method.setAccessible(true);
        @SuppressWarnings("unchecked") List<String> result = (List<String>) method.invoke(null, url);

        assertTrue(result.isEmpty());
    }

    @Test
    public void testExtractResponseUrisFromUrlWithNoResponseUriParameter() throws Exception {
        String url = "https://example.com?other_param=value&another_param=value2";

        Method method = ClientValidationUtils.class.getDeclaredMethod("extractResponseUrisFromUrl", String.class);
        method.setAccessible(true);
        @SuppressWarnings("unchecked") List<String> result = (List<String>) method.invoke(null, url);

        assertTrue(result.isEmpty());
    }

    @Test
    public void testExtractResponseUrisFromUrlWithMalformedParameter() throws Exception {
        String url = "https://example.com?response_uri&other_param=value";

        Method method = ClientValidationUtils.class.getDeclaredMethod("extractResponseUrisFromUrl", String.class);
        method.setAccessible(true);
        @SuppressWarnings("unchecked") List<String> result = (List<String>) method.invoke(null, url);

        assertTrue(result.isEmpty());
    }

    @Test
    public void testExtractResponseUrisFromUrlWithException() throws Exception {
        String url = null;

        Method method = ClientValidationUtils.class.getDeclaredMethod("extractResponseUrisFromUrl", String.class);
        method.setAccessible(true);
        @SuppressWarnings("unchecked") List<String> result = (List<String>) method.invoke(null, url);

        assertTrue(result.isEmpty());
    }

    @Test
    public void testExtractResponseUrisFromUrlWithEmptyValue() throws Exception {
        String url = "https://example.com?response_uri=&other_param=value";

        Method method = ClientValidationUtils.class.getDeclaredMethod("extractResponseUrisFromUrl", String.class);
        method.setAccessible(true);
        @SuppressWarnings("unchecked") List<String> result = (List<String>) method.invoke(null, url);

        assertEquals(1, result.size());
        assertEquals("", result.get(0));
    }

    @Test
    public void testExtractResponseUrisFromUrlWithCommaOnly() throws Exception {
        String url = "https://example.com?response_uri=,"; // Direct comma

        Method method = ClientValidationUtils.class.getDeclaredMethod("extractResponseUrisFromUrl", String.class);
        method.setAccessible(true);
        @SuppressWarnings("unchecked") List<String> result = (List<String>) method.invoke(null, url);

        assertFalse(result.isEmpty());
    }

    @Test
    public void testIsClientValidWithSpecialCharactersInClientId() {
        String specialClientId = "https://test.com/path?param=value&other=123";
        String encodedSpecialClientId = "https%3A%2F%2Ftest.com%2Fpath%3Fparam%3Dvalue%26other%3D123";
        List<Verifier> verifiers = List.of(new Verifier(specialClientId, List.of(VALID_RESPONSE_URI), null));
        String url = "https://example.com?client_id=" + encodedSpecialClientId;

        boolean result = ClientValidationUtils.isVerifierClientPreregistered(verifiers, url);

        assertTrue(result);
    }

    @Test
    public void testIsClientValidWithSpecialCharactersInResponseUri() {
        String specialResponseUri = "https://test.com/callback?param=value&other=123";
        String encodedSpecialResponseUri = "https%3A%2F%2Ftest.com%2Fcallback%3Fparam%3Dvalue%26other%3D123";
        List<Verifier> verifiers = List.of(new Verifier(VALID_CLIENT_ID, List.of(specialResponseUri), null));
        String url = "https://example.com?client_id=" + ENCODED_CLIENT_ID + "&response_uri=" + encodedSpecialResponseUri;

        boolean result = ClientValidationUtils.isVerifierClientPreregistered(verifiers, url);

        assertTrue(result);
    }

    @Test
    public void testIsClientValidWithMultipleVerifiers() {
        List<Verifier> verifiers = Arrays.asList(new Verifier("https://verifier1.com", List.of("https://callback1.com"), null), new Verifier(VALID_CLIENT_ID, List.of(VALID_RESPONSE_URI), null), new Verifier("https://verifier3.com", List.of("https://callback3.com"), null));
        String url = "https://example.com?client_id=" + ENCODED_CLIENT_ID + "&response_uri=" + ENCODED_RESPONSE_URI;

        boolean result = ClientValidationUtils.isVerifierClientPreregistered(verifiers, url);

        assertTrue(result);
    }
}
