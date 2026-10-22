package io.mosip.mimoto.service.device;

import io.mosip.mimoto.config.device.DeviceAttestationProperties;
import io.mosip.mimoto.dto.device.PlayIntegrityDecodeResponse;
import io.mosip.mimoto.dto.device.PlayIntegrityDecodeResponse.AppIntegrity;
import io.mosip.mimoto.dto.device.PlayIntegrityDecodeResponse.DeviceIntegrity;
import io.mosip.mimoto.dto.device.PlayIntegrityDecodeResponse.RequestDetails;
import io.mosip.mimoto.dto.device.PlayIntegrityDecodeResponse.TokenPayloadExternal;
import io.mosip.mimoto.exception.DeviceAttestationException;
import io.mosip.mimoto.model.DevicePlatform;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import static io.mosip.mimoto.exception.ErrorConstants.ATTESTATION_FAILED;
import static io.mosip.mimoto.exception.ErrorConstants.SERVER_UNAVAILABLE;

/**
 * Verifies Play Integrity classic-request tokens by decoding them on Google's servers.
 */
@Slf4j
@Component
public class PlayIntegrityVerifier implements DeviceAttestationVerifier {

    static final String SCOPE = "https://www.googleapis.com/auth/playintegrity";
    static final String DECODE_URL = "https://playintegrity.googleapis.com/v1/{packageName}:decodeIntegrityToken";
    static final String PLAY_RECOGNIZED = "PLAY_RECOGNIZED";
    // Tolerated device clock drift for tokens that appear to come from the future
    private static final Duration FUTURE_SKEW = Duration.ofSeconds(60);

    private final RestTemplate restTemplate;
    private final GoogleServiceAccountTokenProvider tokenProvider;
    private final DeviceAttestationProperties.Android config;
    private final Clock clock;

    @Autowired
    public PlayIntegrityVerifier(@Qualifier("playIntegrityRestTemplate") RestTemplate restTemplate,
                                 GoogleServiceAccountTokenProvider tokenProvider,
                                 DeviceAttestationProperties properties) {
        this(restTemplate, tokenProvider, properties, Clock.systemUTC());
    }

    PlayIntegrityVerifier(RestTemplate restTemplate, GoogleServiceAccountTokenProvider tokenProvider,
                          DeviceAttestationProperties properties, Clock clock) {
        this.restTemplate = restTemplate;
        this.tokenProvider = tokenProvider;
        this.config = properties.getAndroid();
        this.clock = clock;
    }

    @Override
    public DevicePlatform platform() {
        return DevicePlatform.ANDROID;
    }

    @Override
    public Map<String, Object> verify(String integrityToken, String expectedNonce) {
        if (StringUtils.isBlank(config.getPackageName()) || config.getCertSha256Digests().isEmpty()) {
            throw new DeviceAttestationException(ATTESTATION_FAILED,
                    "Play Integrity package name or certificate digests are not configured");
        }
        if (StringUtils.isBlank(integrityToken)) {
            throw new DeviceAttestationException(ATTESTATION_FAILED, "Integrity token is missing");
        }
        TokenPayloadExternal payload = decode(integrityToken);
        RequestDetails request = required(payload.requestDetails(), "requestDetails");
        AppIntegrity app = required(payload.appIntegrity(), "appIntegrity");
        DeviceIntegrity device = required(payload.deviceIntegrity(), "deviceIntegrity");

        check(config.getPackageName().equals(request.requestPackageName()), "request package name mismatch");
        check(nonceMatches(expectedNonce, request.nonce()), "nonce mismatch");
        checkFresh(request.timestampMillis());
        boolean showcaseApp = config.isAllowUnrecognizedApp()
                && "UNRECOGNIZED_VERSION".equals(app.appRecognitionVerdict());
        check(PLAY_RECOGNIZED.equals(app.appRecognitionVerdict()) || showcaseApp,
                "app not recognized by Play: " + app.appRecognitionVerdict());
        check(config.getPackageName().equals(app.packageName()), "app package name mismatch");
        List<String> digests = Objects.requireNonNullElse(app.certificateSha256Digest(), List.of());
        check(anyDigestAllowed(digests), "app signing certificate not allowed");
        List<String> deviceVerdicts = Objects.requireNonNullElse(device.deviceRecognitionVerdict(), List.of());
        check(deviceVerdicts.stream().anyMatch(config.getRequiredDeviceVerdicts()::contains),
                "device verdict not accepted: " + deviceVerdicts);
        if (showcaseApp) {
            log.warn("SHOWCASE: accepting UNRECOGNIZED_VERSION for {} with an allowed signing certificate; "
                    + "disable wallet.device-attestation.android.allow-unrecognized-app in production", app.packageName());
        }

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("appRecognitionVerdict", app.appRecognitionVerdict());
        summary.put("versionCode", app.versionCode());
        summary.put("deviceRecognitionVerdict", deviceVerdicts);
        summary.put("timestampMillis", request.timestampMillis());
        return summary;
    }

    private TokenPayloadExternal decode(String integrityToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(tokenProvider.getAccessToken(SCOPE));
        try {
            PlayIntegrityDecodeResponse response = restTemplate.postForObject(DECODE_URL,
                    new HttpEntity<>(Map.of("integrityToken", integrityToken), headers),
                    PlayIntegrityDecodeResponse.class, config.getPackageName());
            return required(response == null ? null : response.tokenPayloadExternal(), "tokenPayloadExternal");
        } catch (HttpClientErrorException e) {
            throw new DeviceAttestationException(ATTESTATION_FAILED, "Google rejected the integrity token: " + e.getStatusCode(), e);
        } catch (RestClientException e) {
            throw new DeviceAttestationException(SERVER_UNAVAILABLE, "Play Integrity API is unavailable", e);
        }
    }

    private void checkFresh(String timestampMillis) {
        long issuedAt;
        try {
            issuedAt = Long.parseLong(timestampMillis);
        } catch (NumberFormatException e) {
            throw new DeviceAttestationException(ATTESTATION_FAILED, "invalid token timestamp");
        }
        Instant issued = Instant.ofEpochMilli(issuedAt);
        Instant now = clock.instant();
        check(!issued.isAfter(now.plus(FUTURE_SKEW)), "token timestamp is in the future");
        check(!issued.isBefore(now.minusSeconds(config.getMaxTokenAgeSeconds())), "token is too old");
    }

    /** Google may return the URL-safe Base64 nonce with padding even when the request omitted it. */
    private static boolean nonceMatches(String expected, String actual) {
        if (expected == null || actual == null) {
            return false;
        }
        try {
            return MessageDigest.isEqual(Base64.getUrlDecoder().decode(expected),
                    Base64.getUrlDecoder().decode(actual));
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private boolean anyDigestAllowed(List<String> verdictDigests) {
        Set<String> allowed = config.getCertSha256Digests().stream()
                .map(PlayIntegrityVerifier::digestHex)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
        return verdictDigests.stream().map(PlayIntegrityVerifier::digestHex).anyMatch(allowed::contains);
    }

    /**
     * Normalises a SHA-256 certificate digest to lower-case hex. The verdict reports it as web-safe base64,
     * while Play Console shows colon-separated hex, so configuration may use either form.
     *
     * @return the hex digest, or null when the value is not a 32-byte digest in a recognised form
     */
    static String digestHex(String digest) {
        if (StringUtils.isBlank(digest)) {
            return null;
        }
        String value = digest.trim();
        String hex = value.replace(":", "");
        if (hex.matches("^[0-9A-Fa-f]{64}$")) {
            return hex.toLowerCase(Locale.ROOT);
        }
        try {
            byte[] bytes = Base64.getUrlDecoder().decode(value.replace('+', '-').replace('/', '_'));
            return bytes.length == 32 ? HexFormat.of().formatHex(bytes) : null;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static <T> T required(T value, String name) {
        if (value == null) {
            throw new DeviceAttestationException(ATTESTATION_FAILED, "verdict is missing " + name);
        }
        return value;
    }

    private static void check(boolean condition, String failure) {
        if (!condition) {
            throw new DeviceAttestationException(ATTESTATION_FAILED, failure);
        }
    }
}
