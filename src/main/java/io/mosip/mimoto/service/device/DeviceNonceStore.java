package io.mosip.mimoto.service.device;

import java.time.Duration;

/**
 * Bucket of issued nonces. A nonce is accepted once: consuming it removes it.
 */
public interface DeviceNonceStore {

    void put(String nonce, Duration ttl);

    /**
     * Removes the nonce atomically.
     *
     * @return true if the nonce was in the bucket and had not expired
     */
    boolean consume(String nonce);
}
