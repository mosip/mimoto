package io.mosip.mimoto.service.device;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Nonce bucket shared by all mimoto instances. GETDEL makes consumption single-use across pods.
 */
@Component
@ConditionalOnProperty(name = "spring.cache.type", havingValue = "redis")
public class RedisDeviceNonceStore implements DeviceNonceStore {

    static final String KEY_PREFIX = "injiweb:device-nonce:";
    private static final String PRESENT = "1";

    private final StringRedisTemplate redisTemplate;

    public RedisDeviceNonceStore(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void put(String nonce, Duration ttl) {
        redisTemplate.opsForValue().set(KEY_PREFIX + nonce, PRESENT, ttl);
    }

    @Override
    public boolean consume(String nonce) {
        return redisTemplate.opsForValue().getAndDelete(KEY_PREFIX + nonce) != null;
    }
}
