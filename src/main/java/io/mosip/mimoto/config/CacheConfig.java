package io.mosip.mimoto.config;

import java.util.Objects;
import java.util.concurrent.TimeUnit;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Value;

@Configuration
@EnableCaching
public class CacheConfig {

    @Value("${cache.credential.issuer.wellknown.response.expiry-time-in-min:60}")
    private Long issuerWellknownExpiryTimeInMin;

    @Value("${cache.issuers.config.expiry-time-in-min:60}")
    private Long issuersConfigExpiryTimeInMin;

    @Value("${cache.credential.issuer.authserver.wellknown.response.expiry-time-in-min:60}")
    private Long authServerWellknownExpiryTimeInMin;

    @Value("${cache.default.expiry-time-in-min:60}")
    private long defaultCacheExpiryTimeInMin;

    private Caffeine<Object, Object> buildCache(Long expiryTime) {
        return Caffeine.newBuilder().expireAfterWrite(
                Objects.requireNonNullElse(expiryTime, defaultCacheExpiryTimeInMin), TimeUnit.MINUTES
        );
    }


    @Bean
    public CacheManager cacheManager() {
        CaffeineCacheManager cacheManager = new CaffeineCacheManager();
        cacheManager.registerCustomCache("issuerWellknown", buildCache(issuerWellknownExpiryTimeInMin).build());
        cacheManager.registerCustomCache("issuersConfig", buildCache(issuersConfigExpiryTimeInMin).build());
        cacheManager.registerCustomCache("authServerWellknown", buildCache(authServerWellknownExpiryTimeInMin).build());
        cacheManager.setCaffeine(buildCache(null));
        return cacheManager;
    }
}
