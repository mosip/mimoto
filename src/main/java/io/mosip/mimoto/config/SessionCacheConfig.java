package io.mosip.mimoto.config;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Cache;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.config.annotation.web.http.EnableSpringHttpSession;
import org.springframework.session.Session;

import java.time.Duration;

/**
 * Configuration for HTTP session store.
 *
 * A Caffeine-backed MapSessionRepository will be created only when the
 * 'spring.session.store-type' property is explicitly set to 'caffeine'.
 *
 * When the 'spring.session.store-type' property is set to a supported Spring
 * Session provider such as 'redis', 'jdbc', or 'mongo', Spring Boot will
 * automatically create the appropriate built-in SessionRepository and the
 * Caffeine-based repository defined in this class will not be used.
 *
 * If the property is not set (or is set to an unsupported value), Spring will
 * not create the Caffeine bean and will either fall back to the default
 * in-memory session repository or fail to start (in case of invalid value).
 */
@Configuration
@EnableSpringHttpSession
@Slf4j
public class SessionCacheConfig {

    @Value("${server.servlet.session.timeout:30m}")
    private Duration springSessionTimeout;

    @Bean
    @ConditionalOnProperty(name = "spring.session.store-type", havingValue = "caffeine")
    public MapSessionRepository caffeineSessionRepository() {
        log.info("******* Initializing session repository using Caffeine cache provider *******");
        Cache<String, Session> sessionCache = Caffeine.newBuilder()
                .expireAfterAccess(springSessionTimeout)
                .maximumSize(2000)
                .build();

        return new MapSessionRepository(sessionCache.asMap());
    }
}

