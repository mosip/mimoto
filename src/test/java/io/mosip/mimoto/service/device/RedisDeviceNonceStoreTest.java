package io.mosip.mimoto.service.device;

import org.junit.Before;
import org.junit.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class RedisDeviceNonceStoreTest {

    private ValueOperations<String, String> valueOperations;
    private RedisDeviceNonceStore store;

    @Before
    @SuppressWarnings("unchecked")
    public void setUp() {
        StringRedisTemplate redisTemplate = mock(StringRedisTemplate.class);
        valueOperations = mock(ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        store = new RedisDeviceNonceStore(redisTemplate);
    }

    @Test
    public void should_storeNonceWithTtlUnderPrefix_when_put() {
        store.put("abc", Duration.ofSeconds(120));

        verify(valueOperations).set("injiweb:device-nonce:abc", "1", Duration.ofSeconds(120));
    }

    @Test
    public void should_returnTrueOnce_when_getAndDeleteFindsNonce() {
        when(valueOperations.getAndDelete("injiweb:device-nonce:abc")).thenReturn("1").thenReturn(null);

        assertTrue(store.consume("abc"));
        assertFalse(store.consume("abc"));
    }
}
