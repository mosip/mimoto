package io.mosip.mimoto.util;

import com.nimbusds.jose.util.Base64URL;
import lombok.experimental.UtilityClass;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Utility class for Base64URL encoding and decoding operations.
 * Provides centralized Base64URL functionality using both Java standard library
 * and Nimbus JOSE library for consistency across the application.
 */
@UtilityClass
public class Base64Util {

    /**
     * Encodes a string to Base64URL format using Nimbus JOSE library
     *
     * @param input the string to encode
     * @return Base64URL encoded string
     */
    public static String encode(String input) {
        if (input == null) {
            return null;
        }
        return Base64URL.encode(input.getBytes(StandardCharsets.UTF_8)).toString();
    }

    /**
     * Encodes a byte array to Base64URL format using Nimbus JOSE library
     *
     * @param bytes the byte array to encode
     * @return Base64URL encoded string
     */
    public static String encode(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        return Base64URL.encode(bytes).toString();
    }

    /**
     * Decodes a Base64URL string to byte array using Nimbus JOSE library
     *
     * @param base64UrlString the Base64URL encoded string
     * @return decoded byte array
     * @throws IllegalArgumentException if the input is not valid Base64URL
     */
    public static byte[] decode(String base64UrlString) {
        if (base64UrlString == null) {
            return null;
        }
        return Base64URL.from(base64UrlString).decode();
    }

    /**
     * Decodes a Base64URL string to a UTF-8 string using Nimbus JOSE library
     *
     * @param base64UrlString the Base64URL encoded string
     * @return decoded UTF-8 string
     * @throws IllegalArgumentException if the input is not valid Base64URL
     */
    public static String decodeToString(String base64UrlString) {
        byte[] decoded = decode(base64UrlString);
        return decoded != null ? new String(decoded, StandardCharsets.UTF_8) : null;
    }

    /**
     * Alternative encoding method using Java standard library for compatibility
     *
     * @param input the string to encode
     * @return Base64URL encoded string using Java standard library
     */
    public static String encodeWithJavaStdLib(String input) {
        if (input == null) {
            return null;
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(input.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Alternative encoding method using Java standard library for compatibility
     *
     * @param bytes the byte array to encode
     * @return Base64URL encoded string using Java standard library
     */
    public static String encodeWithJavaStdLib(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Alternative decoding method using Java standard library for compatibility
     *
     * @param base64UrlString the Base64URL encoded string
     * @return decoded byte array using Java standard library
     * @throws IllegalArgumentException if the input is not valid Base64URL
     */
    public static byte[] decodeWithJavaStdLib(String base64UrlString) {
        if (base64UrlString == null) {
            return null;
        }
        return Base64.getUrlDecoder().decode(base64UrlString);
    }

    /**
     * Converts a Base64 or Base64URL string to byte array with automatic format detection.
     * This method tries Base64URL decoding first (common for JWT/VP tokens),
     * then falls back to standard Base64, and finally normalizes and retries if both fail.
     *
     * @param base64String the Base64 or Base64URL encoded string
     * @return decoded byte array
     * @throws IllegalArgumentException if the input cannot be decoded in any supported format
     */
    public static byte[] decodeFlexible(String base64String) {
        if (base64String == null) {
            return null;
        }

        try {
            // First try Base64URL decoding (which is more common for JWT/VP tokens)
            return Base64.getUrlDecoder().decode(base64String);
        } catch (IllegalArgumentException e) {
            try {
                // Fallback to standard Base64 decoding
                return Base64.getDecoder().decode(base64String);
            } catch (IllegalArgumentException e2) {
                // If both fail, normalize to standard Base64 and try again
                String normalizedBase64 = normalizeBase64String(base64String);
                return Base64.getDecoder().decode(normalizedBase64);
            }
        }
    }

    /**
     * Normalizes a Base64URL string to standard Base64 format with proper padding.
     * Converts '-' to '+', '_' to '/', and adds padding ('=') if needed.
     *
     * @param base64String the Base64URL string to normalize
     * @return normalized standard Base64 string with padding
     */
    public static String normalizeBase64String(String base64String) {
        if (base64String == null) {
            return null;
        }

        StringBuilder standardBase64 = new StringBuilder(base64String.replace('-', '+').replace('_', '/'));

        // Add padding if needed
        while (standardBase64.length() % 4 != 0) {
            standardBase64.append("=");
        }

        return standardBase64.toString();
    }

    /**
     * Creates a detached JWT signing input by concatenating header and payload bytes with a period ('.') separator.
     * This is used for creating the input to sign for detached JWTs where the payload is not included in the final JWT.
     * Uses ByteBuffer for efficient byte array concatenation.
     * <p>
     * Format: base64url(header) + '.' + payload_bytes
     *
     * @param headerBase64 the Base64URL encoded header string
     * @param payloadBytes the payload bytes to be signed
     * @return byte array containing header bytes + '.' + payload bytes
     */
    public static byte[] createDetachedJwtSigningInput(String headerBase64, byte[] payloadBytes) {
        if (headerBase64 == null || payloadBytes == null) {
            throw new IllegalArgumentException("Header and payload cannot be null");
        }

        byte[] headerBytes = headerBase64.getBytes(StandardCharsets.UTF_8);
        byte periodByte = (byte) '.'; // ASCII 46

        // Use ByteBuffer for cleaner byte array concatenation
        ByteBuffer buffer = ByteBuffer.allocate(headerBytes.length + 1 + payloadBytes.length);
        buffer.put(headerBytes);
        buffer.put(periodByte);
        buffer.put(payloadBytes);

        return buffer.array();
    }
}
