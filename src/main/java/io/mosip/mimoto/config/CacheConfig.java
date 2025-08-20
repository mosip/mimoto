package io.mosip.mimoto.config;

import java.time.Duration;
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
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializationContext;
import org.springframework.data.redis.serializer.RedisSerializer;

/**
 * Cache configuration for the application.
 *
 * Two cache manager beans are provided:
 *
 * 1. CaffeineCacheManager – used when 'spring.cache.type=caffeine'.
 *    This cache manager is created explicitly in this configuration class and
 *    allows us to customize the Caffeine configuration (e.g. per-cache TTLs, size).
 *
 * 2. RedisCacheManager – used when 'spring.cache.type=redis'.
 *    This bean is created only when the Redis cache type is configured and
 *    gives us full control over the Redis cache configuration (value serializer,
 *    per-cache TTLs, etc.).
 *
 * If 'spring.cache.type' is not set, Spring Boot will auto-detect the cache
 * provider based on the libraries on the classpath (e.g. Caffeine or Redis), or
 * fall back to the SimpleCacheManager (in-memory ConcurrentHashMap) if no cache
 * library is available.
 *
 * NOTE: If 'spring.cache.type' is set to an invalid or unsupported value,
 * the application will fail to start. Spring Boot does not fall back to a
 * default cache manager in that case.
 */
@Configuration
@EnableCaching
@Slf4j
public class CacheConfig {

    private static final String ISSUER_WELLKNOWN_CACHE = "issuerWellknown";
    private static final String ISSUERS_CONFIG_CACHE   = "issuersConfig";
    private static final String AUTH_SERVER_WELLKNOWN_CACHE = "authServerWellknown";

    @Value("${cache.credential-issuer.wellknown.expiry-time-in-min:60}")
    private Long issuerWellknownExpiryTimeInMin;

    @Value("${cache.issuers-config.expiry-time-in-min:60}")
    private Long issuersConfigExpiryTimeInMin;

    @Value("${cache.credential-issuer.authserver-wellknown.expiry-time-in-min:60}")
    private Long authServerWellknownExpiryTimeInMin;

    @Value("${cache.default.expiry-time-in-min:60}")
    private long defaultCacheExpiryTimeInMin;

    private Caffeine<Object, Object> createCaffeineCacheConfig(Long expiryTime) {
        return Caffeine.newBuilder().expireAfterWrite(
                Objects.requireNonNullElse(expiryTime, defaultCacheExpiryTimeInMin), TimeUnit.MINUTES
        );
    }


    @Bean
    @ConditionalOnProperty(name = "spring.cache.type", havingValue = "caffeine")
    public CacheManager caffeineCacheManager() {
        log.info("******* Initializing Caffeine cache provider *******");

        CaffeineCacheManager cacheManager = new CaffeineCacheManager();
        cacheManager.registerCustomCache(ISSUER_WELLKNOWN_CACHE, createCaffeineCacheConfig(issuerWellknownExpiryTimeInMin).build());
        cacheManager.registerCustomCache(ISSUERS_CONFIG_CACHE, createCaffeineCacheConfig(issuersConfigExpiryTimeInMin).build());
        cacheManager.registerCustomCache(AUTH_SERVER_WELLKNOWN_CACHE, createCaffeineCacheConfig(authServerWellknownExpiryTimeInMin).build());
        cacheManager.setCaffeine(createCaffeineCacheConfig(null));

        return cacheManager;
    }

    private RedisCacheConfiguration createRedisCacheConfig(Long expiryTime,
                                                           RedisSerializer<Object> serializer) {
        return RedisCacheConfiguration.defaultCacheConfig()
                .serializeValuesWith(RedisSerializationContext.SerializationPair.fromSerializer(serializer))
                .entryTtl(Duration.ofMinutes(Objects.requireNonNullElse(expiryTime, defaultCacheExpiryTimeInMin)));
    }

    @Bean
    @ConditionalOnProperty(name = "spring.cache.type", havingValue = "redis")
    public RedisCacheManager redisCacheManager(RedisConnectionFactory connectionFactory) {
        log.info("******* Initializing Redis cache provider *********");
        GenericJackson2JsonRedisSerializer jacksonSerializer = new GenericJackson2JsonRedisSerializer();

        // Default config
        RedisCacheConfiguration defaultCacheConfig = createRedisCacheConfig(defaultCacheExpiryTimeInMin, jacksonSerializer)
                .disableCachingNullValues();

        // Per-cache configs
        Map<String, RedisCacheConfiguration> cacheConfigurations = Map.of(
                ISSUER_WELLKNOWN_CACHE, createRedisCacheConfig(issuerWellknownExpiryTimeInMin, jacksonSerializer),
                ISSUERS_CONFIG_CACHE, createRedisCacheConfig(issuersConfigExpiryTimeInMin, jacksonSerializer),
                AUTH_SERVER_WELLKNOWN_CACHE, createRedisCacheConfig(authServerWellknownExpiryTimeInMin, jacksonSerializer)
        );

        return RedisCacheManager.builder(connectionFactory)
                .cacheDefaults(defaultCacheConfig)
                .withInitialCacheConfigurations(cacheConfigurations)
                .build();
    }
}
