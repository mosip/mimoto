package io.mosip.mimoto.dto.device;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Subset of the Play Integrity v1 {@code decodeIntegrityToken} response that mimoto checks.
 * Field names follow the API's discovery document.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record PlayIntegrityDecodeResponse(TokenPayloadExternal tokenPayloadExternal) {

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record TokenPayloadExternal(RequestDetails requestDetails,
                                       AppIntegrity appIntegrity,
                                       DeviceIntegrity deviceIntegrity) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record RequestDetails(String requestPackageName, String nonce, String timestampMillis) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record AppIntegrity(String appRecognitionVerdict, String packageName,
                               List<String> certificateSha256Digest, String versionCode) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record DeviceIntegrity(List<String> deviceRecognitionVerdict) {
    }
}
