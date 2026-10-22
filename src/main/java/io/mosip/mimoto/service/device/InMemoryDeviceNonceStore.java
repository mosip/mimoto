package io.mosip.mimoto.service.device;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Nonce bucket held in this instance's memory, used when Redis is not the cache (e.g. the local profile).
 * Nonces are not shared across instances, so this is only correct for a single-instance deployment.
 */
@Slf4j
@Component
@ConditionalOnExpression("'${spring.cache.type:}' != 'redis'")
public class InMemoryDeviceNonceStore implements DeviceNonceStore {

    private static final long MAX_NONCES = 100_000;

    private final Cache<String, Long> nonces = Caffeine.newBuilder()
            .maximumSize(MAX_NONCES)
            .expireAfter(new Expiry<String, Long>() {
                @Override
                public long expireAfterCreate(String key, Long ttlNanos, long currentTime) {
                    return ttlNanos;
                }

                @Override
                public long expireAfterUpdate(String key, Long ttlNanos, long currentTime, long currentDuration) {
                    return ttlNanos;
                }

                @Override
                public long expireAfterRead(String key, Long ttlNanos, long currentTime, long currentDuration) {
                    return currentDuration;
                }
            })
            .build();

    public InMemoryDeviceNonceStore() {
        log.warn("Device nonces are kept in memory; use Redis when running more than one mimoto instance");
    }

    @Override
    public void put(String nonce, Duration ttl) {
        nonces.put(nonce, ttl.toNanos());
    }

    @Override
    public boolean consume(String nonce) {
        return nonces.asMap().remove(nonce) != null;
    }
}
