package io.mosip.residentapp.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import io.mosip.kernel.auth.defaultadapter.filter.AuthFilter;
import io.mosip.kernel.auth.defaultadapter.filter.CorsFilter;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.residentapp.util.LoggerUtil;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Order(1)
public class Config extends WebSecurityConfigurerAdapter {
    private Logger logger = LoggerUtil.getLogger(Config.class);

    @Value("${mosipbox.public.url}")
    private String baseUrl;

    @Value("${mosip.security.csrf-enable:false}")
    private boolean isCSRFEnable;

    @Value("${mosip.security.cors-enable:false}")
    private boolean isCORSEnable;

    @Value("${mosip.security.origins:localhost:8080}")
    private String origins;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        if (!isCSRFEnable) {
            http = http.csrf().disable();
        }
        // http.authorizeRequests().antMatchers("*").authenticated().and().exceptionHandling()
        // .authenticationEntryPoint(new AuthEntryPoint()).and().sessionManagement()
        // .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        // http.addFilterBefore(authFilter(),
        // UsernamePasswordAuthenticationFilter.class);

        // FIXME: web security is disabled for all enpoints
        http.authorizeRequests().antMatchers("*").authenticated().anyRequest().permitAll().and().exceptionHandling();
        if (isCORSEnable) {
            http.addFilterBefore(new CorsFilter(origins), AuthFilter.class);
        }
        http.headers().cacheControl();
        http.headers().frameOptions().sameOrigin();

    }

    @Bean
    public TaskScheduler taskScheduler() {
        ThreadPoolTaskScheduler threadPoolTaskScheduler = new ThreadPoolTaskScheduler();
        threadPoolTaskScheduler.setPoolSize(5);
        threadPoolTaskScheduler.setThreadNamePrefix("ThreadPoolTaskScheduler");
        return threadPoolTaskScheduler;
    }
}
