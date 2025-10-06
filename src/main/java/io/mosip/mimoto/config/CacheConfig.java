package io.mosip.mimoto.config;

import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import com.github.benmanes.caffeine.cache.Caffeine;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.cache.CacheManagerCustomizer;
import org.springframework.boot.autoconfigure.cache.RedisCacheManagerBuilderCustomizer;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializationContext;

/**
 * Cache configuration for the application.
 *
 * This class provides customizers to configure two cache providers based on
 * the 'spring.cache.type' property.
 *
 * 1. CaffeineCacheManager – configured by a `CacheManagerCustomizer` bean,
 * allowing customization of specific cache settings like per-cache TTLs,
 * without creating the full bean from scratch.
 *
 * 2. RedisCacheManager – configured by a `RedisCacheManagerBuilderCustomizer` bean,
 * which gives full control over the Redis cache configuration (value serializer,
 * per-cache TTLs, etc.) without creating the full bean from scratch.
 *
 * Both customizer beans are only created if the corresponding cache type is
 * specified. If 'spring.cache.type' is not set, Spring Boot will auto-detect the cache
 * provider based on the libraries on the classpath, or fall back to the
 * SimpleCacheManager (in-memory ConcurrentHashMap) if no cache library is available.
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
    private static final String PRE_REGISTERED_TRUSTED_VERIFIERS_CACHE = "preRegisteredTrustedVerifiers";

    @Value("${cache.credential-issuer.wellknown.expiry-time-in-min:60}")
    private Long issuerWellknownExpiryTimeInMin;

    @Value("${cache.issuers-config.expiry-time-in-min:60}")
    private Long issuersConfigExpiryTimeInMin;

    @Value("${cache.credential-issuer.authserver-wellknown.expiry-time-in-min:60}")
    private Long authServerWellknownExpiryTimeInMin;

    @Value("${cache.pre-registered-trusted-verifiers.expiry-time-in-min:60}")
    private Long preRegisteredTrustedVerifiersExpiryTimeInMin;

    @Value("${cache.default.expiry-time-in-min:60}")
    private long defaultCacheExpiryTimeInMin;

    /**
     * Creates a reusable Caffeine builder configuration.
     *
     * @param expiryTime The custom expiry time in minutes for the cache.
     * @return A configured Caffeine builder instance.
     */
    private Caffeine<Object, Object> createCaffeineCacheConfig(Long expiryTime) {
        return Caffeine.newBuilder().expireAfterWrite(
                Objects.requireNonNullElse(expiryTime, defaultCacheExpiryTimeInMin), TimeUnit.MINUTES
        );
    }

    /**
     * This method defines a CacheManagerCustomizer bean to customize the
     * auto-configured CaffeineCacheManager. It registers custom caches
     * with their specific configurations. This is the preferred Spring Boot approach.
     * This bean is only created if 'spring.cache.type' is set to 'caffeine'.
     *
     * @return A CacheManagerCustomizer instance.
     */
    @Bean
    @ConditionalOnProperty(name = "spring.cache.type", havingValue = "caffeine")
    public CacheManagerCustomizer<CaffeineCacheManager> caffeineCacheManagerCustomizer() {
        log.info("******* Customizing Caffeine cache provider *******");

        return cacheManager -> {
            cacheManager.registerCustomCache(
                    ISSUER_WELLKNOWN_CACHE,
                    createCaffeineCacheConfig(issuerWellknownExpiryTimeInMin).build()
            );
            cacheManager.registerCustomCache(
                    ISSUERS_CONFIG_CACHE,
                    createCaffeineCacheConfig(issuersConfigExpiryTimeInMin).build()
            );
            cacheManager.registerCustomCache(
                    AUTH_SERVER_WELLKNOWN_CACHE,
                    createCaffeineCacheConfig(authServerWellknownExpiryTimeInMin).build()
            );
            cacheManager.registerCustomCache(
                    PRE_REGISTERED_TRUSTED_VERIFIERS_CACHE,
                    createCaffeineCacheConfig(preRegisteredTrustedVerifiersExpiryTimeInMin).build()
            );
            // Set the default Caffeine config for any other caches
            cacheManager.setCaffeine(createCaffeineCacheConfig(null));
        };
    }

    /**
     * This method defines a RedisCacheManagerBuilderCustomizer bean to customize the
     * auto-configured RedisCacheManager. It registers per-cache configurations.
     * This is the preferred Spring Boot approach.
     * This bean is only created if 'spring.cache.type' is set to 'redis'.
     *
     * @return A RedisCacheManagerBuilderCustomizer instance.
     */
    @Bean
    @ConditionalOnProperty(name = "spring.cache.type", havingValue = "redis")
    public RedisCacheManagerBuilderCustomizer redisCacheManagerBuilderCustomizer() {
        log.info("******* Customizing Redis cache provider *********");
        GenericJackson2JsonRedisSerializer jacksonSerializer = new GenericJackson2JsonRedisSerializer();

        return builder -> {
            // Default config for the Redis cache manager
            RedisCacheConfiguration defaultCacheConfig = RedisCacheConfiguration.defaultCacheConfig()
                    .serializeValuesWith(RedisSerializationContext.SerializationPair.fromSerializer(jacksonSerializer))
                    .entryTtl(Duration.ofMinutes(defaultCacheExpiryTimeInMin))
                    .disableCachingNullValues();

            // Per-cache configs
            Map<String, RedisCacheConfiguration> cacheConfigurations = Map.of(
                    ISSUER_WELLKNOWN_CACHE, createRedisConfigWithTtl(defaultCacheConfig, issuerWellknownExpiryTimeInMin),
                    ISSUERS_CONFIG_CACHE, createRedisConfigWithTtl(defaultCacheConfig, issuersConfigExpiryTimeInMin),
                    AUTH_SERVER_WELLKNOWN_CACHE, createRedisConfigWithTtl(defaultCacheConfig, authServerWellknownExpiryTimeInMin),
                    PRE_REGISTERED_TRUSTED_VERIFIERS_CACHE, createRedisConfigWithTtl(defaultCacheConfig, preRegisteredTrustedVerifiersExpiryTimeInMin)
            );

            // Apply default and per-cache configurations
            builder.cacheDefaults(defaultCacheConfig)
                    .withInitialCacheConfigurations(cacheConfigurations);
        };
    }

    /**
     * Helper method to create a RedisCacheConfiguration with a specific TTL.
     *
     * @param baseConfig The base RedisCacheConfiguration.
     * @param expiryTime The expiry time in minutes, with a fallback to the default.
     * @return The new RedisCacheConfiguration with the specified TTL.
     */
    private RedisCacheConfiguration createRedisConfigWithTtl(RedisCacheConfiguration baseConfig, Long expiryTime) {
        return baseConfig.entryTtl(Duration.ofMinutes(Objects.requireNonNullElse(expiryTime, defaultCacheExpiryTimeInMin)));
    }
}