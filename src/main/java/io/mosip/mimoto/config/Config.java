package io.mosip.mimoto.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import io.mosip.kernel.auth.defaultadapter.filter.AuthFilter;
import io.mosip.kernel.auth.defaultadapter.filter.CorsFilter;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.mimoto.util.LoggerUtil;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;

import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@Order(1)
public class Config {
    private Logger logger = LoggerUtil.getLogger(Config.class);

    @Value("${mosipbox.public.url}")
    private String baseUrl;

    @Value("${mosip.security.csrf-enable:false}")
    private boolean isCSRFEnable;

    @Value("${mosip.security.cors-enable:false}")
    private boolean isCORSEnable;

    @Value("${mosip.security.origins:localhost:8080}")
    private String origins;

    @Bean
    @ConfigurationProperties(prefix = "mosip.inji")
    public Map<String, String> injiConfig() {
        return new HashMap<>();
    }

   /* @Override
    protected void configure(HttpSecurity http) throws Exception {

        if (!isCSRFEnable) {
            http = http.csrf().disable();
        }

        // FIXME: web security is disabled for all enpoints
        http.authorizeRequests().antMatchers("*").authenticated().anyRequest().permitAll().and().exceptionHandling();
        if (isCORSEnable) {
            http.addFilterBefore(new CorsFilter(origins), AuthFilter.class);
        }
        http.headers().cacheControl();
        http.headers().frameOptions().sameOrigin();

    }
*/
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        if (!isCSRFEnable) {
            http.csrf(AbstractHttpConfigurer::disable);
        }

        //TODO: exceptionHandling left
        http.authorizeHttpRequests(authorizeRequests -> authorizeRequests
                .requestMatchers("*")
                .authenticated()
                .anyRequest()
                .permitAll()
        );
        http.exceptionHandling(exceptionConfigurer  -> new ExceptionHandlingConfigurer());

        if (isCORSEnable) {
            http.addFilterBefore(new CorsFilter(origins), AuthFilter.class);
        }
        http.headers(headersEntry -> {
            headersEntry.cacheControl(Customizer.withDefaults());
            headersEntry.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin);
        });

        return http.build();

    }

    @Bean
    public TaskScheduler taskScheduler() {
        ThreadPoolTaskScheduler threadPoolTaskScheduler = new ThreadPoolTaskScheduler();
        threadPoolTaskScheduler.setPoolSize(5);
        threadPoolTaskScheduler.setThreadNamePrefix("ThreadPoolTaskScheduler");
        return threadPoolTaskScheduler;
    }
}
