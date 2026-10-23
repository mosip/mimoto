package io.mosip.mimoto.config.device;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * Settings for gating get-token behind a registered wallet device key.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "wallet.device-attestation")
public class DeviceAttestationProperties {

    /**
     * off: no checks. monitor: verify and log, never block. enforce: reject get-token without a valid device proof.
     */
    private Mode mode = Mode.OFF;

    /** Lifetime of a nonce in the bucket, shared by registration and get-token. */
    private long nonceTtlSeconds = 120;

    /** Maximum age of a device proof, measured from its iat. */
    private long proofMaxAgeSeconds = 60;

    private Android android = new Android();

    private Google google = new Google();

    public enum Mode {
        OFF, MONITOR, ENFORCE
    }

    @Getter
    @Setter
    public static class Android {
        /** Package name the integrity token must have been requested for. */
        private String packageName;
        /** Accepted SHA-256 digests of the app signing certificate, as reported by Play Integrity. */
        private List<String> certSha256Digests = new ArrayList<>();
        /** Showcase only: warn for UNRECOGNIZED_VERSION; all other integrity checks remain enforced. */
        private boolean allowUnrecognizedApp = false;
        /** Device verdicts of which at least one must be present. */
        private List<String> requiredDeviceVerdicts = new ArrayList<>(List.of("MEETS_DEVICE_INTEGRITY"));
        /** Maximum age of the integrity token, measured from its requestDetails.timestampMillis. */
        private long maxTokenAgeSeconds = 300;
    }

    @Getter
    @Setter
    public static class Google {
        /** Path of the service account key used to call the Play Integrity decode API. */
        private String serviceAccountKeyPath;
    }
}
