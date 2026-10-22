package io.mosip.mimoto.service.device;

import io.mosip.mimoto.config.device.DeviceAttestationProperties;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * Issues and consumes the single-use nonces used for device registration and device proofs.
 */
@Service
public class DeviceNonceService {

    private static final int NONCE_BYTES = 32;
    // 32 bytes as unpadded base64url
    private static final Pattern NONCE_FORMAT = Pattern.compile("^[A-Za-z0-9_-]{43}$");

    private final DeviceNonceStore store;
    private final Duration ttl;
    private final SecureRandom random = new SecureRandom();

    public DeviceNonceService(DeviceNonceStore store, DeviceAttestationProperties properties) {
        this.store = store;
        this.ttl = Duration.ofSeconds(properties.getNonceTtlSeconds());
    }

    public String issue() {
        byte[] bytes = new byte[NONCE_BYTES];
        random.nextBytes(bytes);
        String nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        store.put(nonce, ttl);
        return nonce;
    }

    public long ttlSeconds() {
        return ttl.toSeconds();
    }

    /**
     * @return true only the first time a nonce issued by this service is presented before it expires
     */
    public boolean consume(String nonce) {
        if (StringUtils.isBlank(nonce) || !NONCE_FORMAT.matcher(nonce).matches()) {
            return false;
        }
        return store.consume(nonce);
    }
}
