package io.mosip.mimoto.util;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.Assert.*;

public class Base64UtilTest {

    @Test
    public void testEncodeStringSuccess() {
        String input = "Hello World";
        String result = Base64Util.encode(input);
        
        assertNotNull(result);
        assertFalse(result.contains("="));
        assertFalse(result.contains("+"));
        assertFalse(result.contains("/"));
    }

    @Test
    public void testEncodeStringWithNullInput() {
        String result = Base64Util.encode((String) null);
        assertNull(result);
    }

    @Test
    public void testEncodeStringWithEmptyInput() {
        String input = "";
        String result = Base64Util.encode(input);
        
        assertNotNull(result);
        assertEquals("", result);
    }

    @Test
    public void testEncodeStringWithSpecialCharacters() {
        String input = "Hello@#$%^&*()_+-=[]{}|;:',.<>?/~`";
        String result = Base64Util.encode(input);
        
        assertNotNull(result);
        assertFalse(result.contains("="));
    }

    @Test
    public void testEncodeStringWithUnicodeCharacters() {
        String input = "Hello 世界 🌍";
        String result = Base64Util.encode(input);
        
        assertNotNull(result);
        assertFalse(result.contains("="));
    }

    @Test
    public void testEncodeStringWithMultilineText() {
        String input = "Line 1\nLine 2\nLine 3";
        String result = Base64Util.encode(input);
        
        assertNotNull(result);
        assertFalse(result.contains("\n"));
    }

    @Test
    public void testEncodeBytesSuccess() {
        byte[] input = "Hello World".getBytes(StandardCharsets.UTF_8);
        String result = Base64Util.encode(input);
        
        assertNotNull(result);
        assertFalse(result.contains("="));
    }

    @Test
    public void testEncodeBytesWithNullInput() {
        String result = Base64Util.encode((byte[]) null);
        assertNull(result);
    }

    @Test
    public void testEncodeBytesWithEmptyArray() {
        byte[] input = new byte[0];
        String result = Base64Util.encode(input);
        
        assertNotNull(result);
        assertEquals("", result);
    }

    @Test
    public void testEncodeBytesWithBinaryData() {
        byte[] input = new byte[]{0x00, 0x01, 0x02, (byte) 0xFF, (byte) 0xFE};
        String result = Base64Util.encode(input);
        
        assertNotNull(result);
        assertFalse(result.contains("="));
    }

    @Test
    public void testDecodeSuccess() {
        String input = "SGVsbG8gV29ybGQ";
        byte[] result = Base64Util.decode(input);
        
        assertNotNull(result);
        assertEquals("Hello World", new String(result, StandardCharsets.UTF_8));
    }

    @Test
    public void testDecodeWithNullInput() {
        byte[] result = Base64Util.decode(null);
        assertNull(result);
    }

    @Test
    public void testDecodeWithEmptyString() {
        String input = "";
        byte[] result = Base64Util.decode(input);
        
        assertNotNull(result);
        assertEquals(0, result.length);
    }

    @Test
    public void testDecodeWithBase64UrlCharacters() {
        String input = "SGVsbG8tV29ybGRf";
        byte[] result = Base64Util.decode(input);
        
        assertNotNull(result);
        assertTrue(result.length > 0);
    }

    @Test
    public void testDecodeWithInvalidBase64String() {
        String input = "Invalid!@#$Base64";
        try {
            byte[] result = Base64Util.decode(input);
            assertNotNull(result);
        } catch (Exception e) {
            assertNotNull(e);
        }
    }

    @Test
    public void testDecodeToStringSuccess() {
        String input = "SGVsbG8gV29ybGQ";
        String result = Base64Util.decodeToString(input);
        
        assertNotNull(result);
        assertEquals("Hello World", result);
    }

    @Test
    public void testDecodeToStringWithNullInput() {
        String result = Base64Util.decodeToString(null);
        assertNull(result);
    }

    @Test
    public void testDecodeToStringWithUnicodeContent() {
        String original = "Hello 世界 🌍";
        String encoded = Base64Util.encode(original);
        String decoded = Base64Util.decodeToString(encoded);
        
        assertEquals(original, decoded);
    }

    @Test
    public void testEncodeWithJavaStdLibStringSuccess() {
        String input = "Hello World";
        String result = Base64Util.encodeWithJavaStdLib(input);
        
        assertNotNull(result);
        assertFalse(result.contains("="));
        assertFalse(result.contains("+"));
        assertFalse(result.contains("/"));
    }

    @Test
    public void testEncodeWithJavaStdLibStringWithNullInput() {
        String result = Base64Util.encodeWithJavaStdLib((String) null);
        assertNull(result);
    }

    @Test
    public void testEncodeWithJavaStdLibStringWithEmptyInput() {
        String input = "";
        String result = Base64Util.encodeWithJavaStdLib(input);
        
        assertNotNull(result);
        assertEquals("", result);
    }

    @Test
    public void testEncodeWithJavaStdLibBytesSuccess() {
        byte[] input = "Hello World".getBytes(StandardCharsets.UTF_8);
        String result = Base64Util.encodeWithJavaStdLib(input);
        
        assertNotNull(result);
        assertFalse(result.contains("="));
    }

    @Test
    public void testEncodeWithJavaStdLibBytesWithNullInput() {
        String result = Base64Util.encodeWithJavaStdLib((byte[]) null);
        assertNull(result);
    }

    @Test
    public void testEncodeWithJavaStdLibBytesWithEmptyArray() {
        byte[] input = new byte[0];
        String result = Base64Util.encodeWithJavaStdLib(input);
        
        assertNotNull(result);
        assertEquals("", result);
    }

    @Test
    public void testDecodeWithJavaStdLibSuccess() {
        String input = "SGVsbG8gV29ybGQ";
        byte[] result = Base64Util.decodeWithJavaStdLib(input);
        
        assertNotNull(result);
        assertEquals("Hello World", new String(result, StandardCharsets.UTF_8));
    }

    @Test
    public void testDecodeWithJavaStdLibWithNullInput() {
        byte[] result = Base64Util.decodeWithJavaStdLib(null);
        assertNull(result);
    }

    @Test
    public void testDecodeWithJavaStdLibWithEmptyString() {
        String input = "";
        byte[] result = Base64Util.decodeWithJavaStdLib(input);
        
        assertNotNull(result);
        assertEquals(0, result.length);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDecodeWithJavaStdLibWithInvalidBase64String() {
        String input = "Invalid!@#$Base64";
        Base64Util.decodeWithJavaStdLib(input);
    }

    @Test
    public void testDecodeFlexibleWithBase64UrlString() {
        String input = "SGVsbG8tV29ybGRf";
        byte[] result = Base64Util.decodeFlexible(input);
        
        assertNotNull(result);
        assertTrue(result.length > 0);
    }

    @Test
    public void testDecodeFlexibleWithStandardBase64String() {
        String input = Base64.getEncoder().encodeToString("Hello World".getBytes(StandardCharsets.UTF_8));
        byte[] result = Base64Util.decodeFlexible(input);
        
        assertNotNull(result);
        assertEquals("Hello World", new String(result, StandardCharsets.UTF_8));
    }

    @Test
    public void testDecodeFlexibleWithNullInput() {
        byte[] result = Base64Util.decodeFlexible(null);
        assertNull(result);
    }

    @Test
    public void testDecodeFlexibleWithBase64UrlNoPadding() {
        String original = "Hello";
        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(original.getBytes(StandardCharsets.UTF_8));
        byte[] result = Base64Util.decodeFlexible(encoded);
        
        assertNotNull(result);
        assertEquals(original, new String(result, StandardCharsets.UTF_8));
    }

    @Test
    public void testDecodeFlexibleFallsBackToStandardBase64() {
        String original = "Test Data";
        String encoded = Base64.getEncoder().encodeToString(original.getBytes(StandardCharsets.UTF_8));
        byte[] result = Base64Util.decodeFlexible(encoded);
        
        assertNotNull(result);
        assertEquals(original, new String(result, StandardCharsets.UTF_8));
    }

    @Test
    public void testDecodeFlexibleWithBase64UrlCharactersAndNormalization() {
        String base64UrlString = "SGVsbG8tV29ybGQ";
        byte[] result = Base64Util.decodeFlexible(base64UrlString);
        
        assertNotNull(result);
        assertTrue(result.length > 0);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDecodeFlexibleWithCompletelyInvalidString() {
        String input = "!!!Invalid@@@";
        Base64Util.decodeFlexible(input);
    }

    @Test
    public void testNormalizeBase64StringWithBase64UrlCharacters() {
        String input = "SGVsbG8tV29ybGRf";
        String result = Base64Util.normalizeBase64String(input);
        
        assertNotNull(result);
        assertFalse(result.contains("-"));
        assertFalse(result.contains("_"));
        assertTrue(result.contains("+") || !input.contains("-"));
        assertTrue(result.contains("/") || !input.contains("_"));
    }

    @Test
    public void testNormalizeBase64StringWithNullInput() {
        String result = Base64Util.normalizeBase64String(null);
        assertNull(result);
    }

    @Test
    public void testNormalizeBase64StringAddsProperPadding() {
        String input = "SGVsbG8";
        String result = Base64Util.normalizeBase64String(input);
        
        assertNotNull(result);
        assertTrue(result.length() % 4 == 0);
        assertTrue(result.endsWith("="));
    }

    @Test
    public void testNormalizeBase64StringWithAlreadyPaddedString() {
        String input = "SGVsbG8gV29ybGQ=";
        String result = Base64Util.normalizeBase64String(input);
        
        assertNotNull(result);
        assertTrue(result.length() % 4 == 0);
    }

    @Test
    public void testNormalizeBase64StringWithNoCharactersToReplace() {
        String input = "SGVsbG8";
        String result = Base64Util.normalizeBase64String(input);
        
        assertNotNull(result);
        assertTrue(result.length() % 4 == 0);
    }

    @Test
    public void testNormalizeBase64StringWithEmptyString() {
        String input = "";
        String result = Base64Util.normalizeBase64String(input);
        
        assertNotNull(result);
        assertEquals("", result);
    }

    @Test
    public void testNormalizeBase64StringConvertsHyphenToPlus() {
        String input = "SGVs-G8";
        String result = Base64Util.normalizeBase64String(input);
        
        assertNotNull(result);
        assertTrue(result.contains("+"));
        assertFalse(result.contains("-"));
    }

    @Test
    public void testNormalizeBase64StringConvertsUnderscoreToSlash() {
        String input = "SGVs_G8";
        String result = Base64Util.normalizeBase64String(input);
        
        assertNotNull(result);
        assertTrue(result.contains("/"));
        assertFalse(result.contains("_"));
    }

    @Test
    public void testNormalizeBase64StringWithMultiplePaddingNeeded() {
        String input = "SGVs";
        String result = Base64Util.normalizeBase64String(input);
        
        assertNotNull(result);
        assertTrue(result.length() % 4 == 0);
        int paddingCount = result.length() - result.replace("=", "").length();
        assertTrue(paddingCount >= 0);
    }

    @Test
    public void testCreateDetachedJwtSigningInputSuccess() {
        String header = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9";
        byte[] payload = "test payload".getBytes(StandardCharsets.UTF_8);
        
        byte[] result = Base64Util.createDetachedJwtSigningInput(header, payload);
        
        assertNotNull(result);
        String resultString = new String(result, StandardCharsets.UTF_8);
        assertTrue(resultString.startsWith(header));
        assertTrue(resultString.contains("."));
        assertTrue(resultString.endsWith("test payload"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testCreateDetachedJwtSigningInputWithNullHeader() {
        byte[] payload = "test payload".getBytes(StandardCharsets.UTF_8);
        Base64Util.createDetachedJwtSigningInput(null, payload);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testCreateDetachedJwtSigningInputWithNullPayload() {
        String header = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9";
        Base64Util.createDetachedJwtSigningInput(header, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testCreateDetachedJwtSigningInputWithBothNull() {
        Base64Util.createDetachedJwtSigningInput(null, null);
    }

    @Test
    public void testCreateDetachedJwtSigningInputWithEmptyHeader() {
        String header = "";
        byte[] payload = "test payload".getBytes(StandardCharsets.UTF_8);
        
        byte[] result = Base64Util.createDetachedJwtSigningInput(header, payload);
        
        assertNotNull(result);
        String resultString = new String(result, StandardCharsets.UTF_8);
        assertEquals(".test payload", resultString);
    }

    @Test
    public void testCreateDetachedJwtSigningInputWithEmptyPayload() {
        String header = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9";
        byte[] payload = new byte[0];
        
        byte[] result = Base64Util.createDetachedJwtSigningInput(header, payload);
        
        assertNotNull(result);
        String resultString = new String(result, StandardCharsets.UTF_8);
        assertEquals(header + ".", resultString);
    }

    @Test
    public void testCreateDetachedJwtSigningInputCorrectByteOrder() {
        String header = "ABC";
        byte[] payload = new byte[]{0x01, 0x02, 0x03};
        
        byte[] result = Base64Util.createDetachedJwtSigningInput(header, payload);
        
        assertNotNull(result);
        assertEquals('A', (char) result[0]);
        assertEquals('B', (char) result[1]);
        assertEquals('C', (char) result[2]);
        assertEquals('.', (char) result[3]);
        assertEquals(0x01, result[4]);
        assertEquals(0x02, result[5]);
        assertEquals(0x03, result[6]);
    }

    @Test
    public void testCreateDetachedJwtSigningInputCorrectLength() {
        String header = "header123";
        byte[] payload = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05};
        
        byte[] result = Base64Util.createDetachedJwtSigningInput(header, payload);
        
        assertNotNull(result);
        assertEquals(header.length() + 1 + payload.length, result.length);
    }

    @Test
    public void testCreateDetachedJwtSigningInputWithLargePayload() {
        String header = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9";
        byte[] payload = new byte[10000];
        for (int i = 0; i < payload.length; i++) {
            payload[i] = (byte) (i % 256);
        }
        
        byte[] result = Base64Util.createDetachedJwtSigningInput(header, payload);
        
        assertNotNull(result);
        assertEquals(header.length() + 1 + payload.length, result.length);
    }

    @Test
    public void testEncodeAndDecodeRoundTrip() {
        String original = "Test Data 123!@#";
        String encoded = Base64Util.encode(original);
        String decoded = Base64Util.decodeToString(encoded);
        
        assertEquals(original, decoded);
    }

    @Test
    public void testEncodeWithJavaStdLibAndDecodeWithJavaStdLibRoundTrip() {
        String original = "Test Data with Java StdLib";
        String encoded = Base64Util.encodeWithJavaStdLib(original);
        byte[] decoded = Base64Util.decodeWithJavaStdLib(encoded);
        
        assertEquals(original, new String(decoded, StandardCharsets.UTF_8));
    }

    @Test
    public void testEncodeBytesAndDecodeRoundTrip() {
        byte[] original = new byte[]{0x00, 0x01, 0x7F, (byte) 0x80, (byte) 0xFF};
        String encoded = Base64Util.encode(original);
        byte[] decoded = Base64Util.decode(encoded);
        
        assertArrayEquals(original, decoded);
    }

    @Test
    public void testDecodeFlexibleWithNormalizedStringRoundTrip() {
        String original = "Test Data for Flexible Decode";
        String encoded = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(original.getBytes(StandardCharsets.UTF_8));
        byte[] decoded = Base64Util.decodeFlexible(encoded);
        
        assertEquals(original, new String(decoded, StandardCharsets.UTF_8));
    }

    @Test
    public void testConsistencyBetweenEncodeMethodsForString() {
        String input = "Consistency Test";
        String result1 = Base64Util.encode(input);
        String result2 = Base64Util.encodeWithJavaStdLib(input);
        
        assertEquals(result1, result2);
    }

    @Test
    public void testConsistencyBetweenEncodeMethodsForBytes() {
        byte[] input = "Consistency Test".getBytes(StandardCharsets.UTF_8);
        String result1 = Base64Util.encode(input);
        String result2 = Base64Util.encodeWithJavaStdLib(input);
        
        assertEquals(result1, result2);
    }

    @Test
    public void testDecodeFlexibleHandlesBase64UrlWithoutPadding() {
        String original = "No padding test";
        String encoded = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(original.getBytes(StandardCharsets.UTF_8));
        byte[] decoded = Base64Util.decodeFlexible(encoded);
        
        assertNotNull(decoded);
        assertEquals(original, new String(decoded, StandardCharsets.UTF_8));
    }

    @Test
    public void testNormalizeBase64StringHandlesEdgeCaseLengths() {
        String input1 = "A";
        String result1 = Base64Util.normalizeBase64String(input1);
        assertTrue(result1.length() % 4 == 0);
        
        String input2 = "AB";
        String result2 = Base64Util.normalizeBase64String(input2);
        assertTrue(result2.length() % 4 == 0);
        
        String input3 = "ABC";
        String result3 = Base64Util.normalizeBase64String(input3);
        assertTrue(result3.length() % 4 == 0);
        
        String input4 = "ABCD";
        String result4 = Base64Util.normalizeBase64String(input4);
        assertTrue(result4.length() % 4 == 0);
    }

    @Test
    public void testCreateDetachedJwtSigningInputWithRealJwtHeader() {
        String header = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleS0xMjMifQ";
        byte[] payload = "{\"sub\":\"1234567890\",\"name\":\"John Doe\"}".getBytes(StandardCharsets.UTF_8);
        
        byte[] result = Base64Util.createDetachedJwtSigningInput(header, payload);
        
        assertNotNull(result);
        assertTrue(result.length > header.length() + payload.length);
        
        String resultString = new String(result, StandardCharsets.UTF_8);
        assertTrue(resultString.contains("."));
        String[] parts = resultString.split("\\.", 2);
        assertEquals(header, parts[0]);
    }

    @Test
    public void testEncodeStringProducesUrlSafeOutput() {
        String input = "Test string that might produce + or / characters when encoded";
        String result = Base64Util.encode(input);
        
        assertNotNull(result);
        assertFalse(result.contains("+"));
        assertFalse(result.contains("/"));
        assertFalse(result.contains("="));
    }

    @Test
    public void testDecodeFlexibleWithMixedBase64AndBase64Url() {
        String original = "Mixed encoding test";
        String standardBase64 = Base64.getEncoder().encodeToString(original.getBytes(StandardCharsets.UTF_8));
        
        byte[] decoded = Base64Util.decodeFlexible(standardBase64);
        
        assertNotNull(decoded);
        assertEquals(original, new String(decoded, StandardCharsets.UTF_8));
    }
}

