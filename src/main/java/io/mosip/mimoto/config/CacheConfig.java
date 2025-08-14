package io.mosip.mimoto.config;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import com.github.benmanes.caffeine.cache.Caffeine;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.cache.RedisCacheManager;
import org.springframework.data.redis.connection.RedisConnectionFactory;

@Configuration
@EnableCaching
@Slf4j
public class CacheConfig {

    @Value("${cache.credential-issuer.wellknown.expiry-time-in-min:60}")
    private Long issuerWellknownExpiryTimeInMin;

    @Value("${cache.issuers-config.expiry-time-in-min:60}")
    private Long issuersConfigExpiryTimeInMin;

    @Value("${cache.credential-issuer.authserver-wellknown.expiry-time-in-min:60}")
    private Long authServerWellknownExpiryTimeInMin;

    @Value("${cache.default.expiry-time-in-min:60}")
    private long defaultCacheExpiryTimeInMin;

    private Caffeine<Object, Object> buildCache(Long expiryTime) {
        return Caffeine.newBuilder().expireAfterWrite(
                Objects.requireNonNullElse(expiryTime, defaultCacheExpiryTimeInMin), TimeUnit.MINUTES
        );
    }


    @Bean
    @ConditionalOnProperty(name = "spring.cache.type", havingValue = "caffeine")
    public CacheManager caffeineCacheManager() {
        log.info("inside caffeine cache config:: {}", defaultCacheExpiryTimeInMin);
        CaffeineCacheManager cacheManager = new CaffeineCacheManager();
        cacheManager.registerCustomCache("issuerWellknown", buildCache(issuerWellknownExpiryTimeInMin).build());
        cacheManager.registerCustomCache("issuersConfig", buildCache(issuersConfigExpiryTimeInMin).build());
        cacheManager.registerCustomCache("authServerWellknown", buildCache(authServerWellknownExpiryTimeInMin).build());
        cacheManager.setCaffeine(buildCache(null));
        return cacheManager;
    }

    @Bean
    @ConditionalOnProperty(name = "spring.cache.type", havingValue = "redis")
    public RedisCacheManager redisCacheManager(RedisConnectionFactory connectionFactory) {
        log.info("inside redis cache config:: {}", defaultCacheExpiryTimeInMin);
        RedisCacheConfiguration defaultCacheConfig = RedisCacheConfiguration.defaultCacheConfig()
                .entryTtl(Duration.ofMinutes(defaultCacheExpiryTimeInMin))
                .disableCachingNullValues();

        // Specific cache configurations with custom TTLs
        Map<String, RedisCacheConfiguration> cacheConfigurations = new HashMap<>();
        cacheConfigurations.put("issuerWellknown", RedisCacheConfiguration.defaultCacheConfig()
                .entryTtl(Duration.ofMinutes(issuerWellknownExpiryTimeInMin)));
        cacheConfigurations.put("issuersConfig", RedisCacheConfiguration.defaultCacheConfig()
                .entryTtl(Duration.ofMinutes(issuersConfigExpiryTimeInMin)));
        cacheConfigurations.put("authServerWellknown", RedisCacheConfiguration.defaultCacheConfig()
                .entryTtl(Duration.ofMinutes(authServerWellknownExpiryTimeInMin)));

        return RedisCacheManager.builder(connectionFactory)
                .cacheDefaults(defaultCacheConfig)
                .withInitialCacheConfigurations(cacheConfigurations)
                .build();
    }
}
