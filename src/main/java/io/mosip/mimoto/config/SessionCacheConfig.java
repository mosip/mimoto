package io.mosip.mimoto.config;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Cache;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.Session;
import org.springframework.session.config.annotation.web.http.EnableSpringHttpSession;

import java.time.Duration;

/**
 * Configuration for HTTP session store.
 *
 * This class provides a MapSessionRepository bean that uses Caffeine as the session store
 * for certain cases and acts as a fallback to ensure the application always has a session repository.
 *
 * Behavior based on 'spring.session.store-type':
 * - If set to 'caffeine': uses the Caffeine-backed repository with TTL and a maximum entry records limit.
 * - If set to 'none', missing, or empty: uses the Caffeine-backed repository as a fallback.
 * - If set to a supported Spring Session provider (e.g., Redis, JDBC, Mongo) and the dependency
 *   is available on the classpath (in pom.xml):
 *     - Spring Boot auto-configures the SessionRepository for that provider.
 *     - The Caffeine repository is ignored.
 * - If set to a supported Spring Session provider but the dependency is NOT available on the classpath:
 *     - The application will fail to start due to a missing SessionRepository bean.
 * - If set to an unsupported or invalid value:
 *     - The application may fail to start unless a valid fallback bean is provided.
 *
 * Notes:
 * - The fallback Caffeine repository ensures safe startup even when no provider is set.
 * - The fallback in-memory repository does not persist sessions across application restarts.
 */
@Configuration
@EnableSpringHttpSession
@Slf4j
public class SessionCacheConfig {

    @Value("${server.servlet.session.timeout:30m}")
    private Duration springSessionTimeout;

    @Bean
    @ConditionalOnExpression(
            "('${spring.session.store-type:none}'.toLowerCase() == 'caffeine') or " +
                    "('${spring.session.store-type:none}'.toLowerCase() == 'none') or " +
                    "T(org.springframework.util.StringUtils).isEmpty('${spring.session.store-type:}')"
    )
    public MapSessionRepository caffeineSessionRepository() {
        log.info("******* Initializing session repository using Caffeine cache provider *******");
        Cache<String, Session> sessionCache = Caffeine.newBuilder()
                .expireAfterAccess(springSessionTimeout)
                .maximumSize(2000)
                .build();
        return new MapSessionRepository(sessionCache.asMap());
    }
}

