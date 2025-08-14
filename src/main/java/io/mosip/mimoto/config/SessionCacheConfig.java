package io.mosip.mimoto.config;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Cache;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.config.annotation.web.http.EnableSpringHttpSession;
import org.springframework.session.Session;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Configuration for the session store.
 * This class provides two beans:
 * 1. A Caffeine-backed MapSessionRepository, which is used when the 'app.session.store-type' property is set to 'caffeine'.
 * 2. A default, simple in-memory MapSessionRepository, which acts as a fallback if the property is not set or has a different value.
 */
@Configuration
@EnableSpringHttpSession
@ConditionalOnProperty(name = "app.running.env", havingValue = "local")
@Slf4j
public class SessionCacheConfig {

    @Value("${server.servlet.session.timeout:30m}")
    private Duration springSessionTimeout;

    /**
     * Creates a MapSessionRepository bean using a Caffeine cache.
     * This bean is only created if 'app.session.store-type' is 'caffeine'.
     *
     * @return a Caffeine-backed MapSessionRepository.
     */
    @Bean
    @ConditionalOnProperty(name = "app.session.store-type", havingValue = "caffeine")
    public MapSessionRepository caffeineSessionRepository() {
        log.info("inside caffeine session cache config:: {}", springSessionTimeout);
        Cache<String, Session> sessionCache = Caffeine.newBuilder()
                .expireAfterAccess(springSessionTimeout)
                .maximumSize(2000)
                .build();

        return new MapSessionRepository(sessionCache.asMap());
    }

    /**
     * Creates a simple in-memory MapSessionRepository as a fallback.
     * This bean will be created only if no other bean of type MapSessionRepository
     * has been created by the Spring application context. This is an ideal
     * fallback for local development or testing when the primary session store
     * is not configured.
     *
     * @return a simple in-memory MapSessionRepository.
     */
    @Bean
    @ConditionalOnMissingBean(MapSessionRepository.class)
    public MapSessionRepository fallbackSessionRepository() {
        log.info("inside caffeine session fallback cache config:: {}", springSessionTimeout);
        return new MapSessionRepository(new ConcurrentHashMap<>());
    }
}

