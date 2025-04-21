package io.mosip.mimoto.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.exception.OAuth2AuthenticationException;
import io.mosip.mimoto.security.oauth2.OAuth2AuthenticationFailureHandler;
import io.mosip.mimoto.security.oauth2.OAuth2AuthenticationSuccessHandler;
import io.mosip.mimoto.service.LogoutService;
import io.mosip.mimoto.util.Utilities;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.session.SessionRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import static io.mosip.mimoto.exception.PlatformErrorMessages.LOGIN_SESSION_INVALIDATE_EXCEPTION;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@Order(1)
@Slf4j
public class Config {

    @Value("${mosipbox.public.url}")
    private String baseUrl;

    @Value("${mosip.security.csrf-enable:false}")
    private boolean isCSRFEnable;

    @Value("${mosip.security.cors-enable:false}")
    private boolean isCORSEnable;

    @Value("${mosip.security.origins:localhost:8088}")
    private String origins;

    @Value("${mosip.security.ignore-auth-urls}")
    private String[] ignoreAuthUrls;

    @Value("${mosip.inji.web.url}")
    private String injiWebUrl;

    @Autowired
    private LogoutService logoutService;

    @Bean
    @ConfigurationProperties(prefix = "mosip.inji")
    public Map<String, String> injiConfig() {
        return new HashMap<>();
    }

    @Autowired
    private OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;

    @Autowired
    private OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, SessionRepository sessionRepository) throws Exception {
        if (!isCSRFEnable) {
            http.csrf(AbstractHttpConfigurer::disable);
        }

        if (isCORSEnable) {
            http.cors(corsCustomizer -> corsCustomizer
                    .configurationSource(corsConfigurationSource()));
        }
        http.headers(headersEntry -> {
            headersEntry.cacheControl(Customizer.withDefaults());
            headersEntry.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin);
        });

        setupOauth2Config(http, sessionRepository);

        http.exceptionHandling(exceptionHandling ->
                exceptionHandling.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
        );


        return http.build();

    }

    private void setupOauth2Config(HttpSecurity http, SessionRepository sessionRepository) throws Exception {
        configureOAuth2Login(http);
        configureLogout(http, sessionRepository);
        configureAuthorization(http);
        configureSessionManagement(http);
    }

    private void configureOAuth2Login(HttpSecurity http) throws Exception {
        http.oauth2Login(oauth2Login -> oauth2Login
                .loginPage(injiWebUrl + "/login")
                .authorizationEndpoint(authorization -> authorization.baseUri("/oauth2/authorize"))
                .redirectionEndpoint(redirect -> redirect.baseUri("/oauth2/callback/*"))
                .successHandler(oAuth2AuthenticationSuccessHandler)
                .failureHandler(oAuth2AuthenticationFailureHandler)
        );
    }

    private void configureLogout(HttpSecurity http, SessionRepository<?> sessionRepository) throws Exception {
        http.logout(logout -> logout
                .invalidateHttpSession(false)
                .clearAuthentication(false)
                .logoutUrl("/logout")
                .logoutSuccessHandler((request, response, authentication) -> {
                    try {
                        logoutService.handleLogout(request, response, sessionRepository);
                    } catch (OAuth2AuthenticationException e) {
                        response.setStatus(e.getStatus().value());
                        response.setContentType("application/json");
                        String jsonResponse = String.format("{\"errors\":[{\"errorCode\":\"%s\",\"errorMessage\":\"%s\"}]}",
                                LOGIN_SESSION_INVALIDATE_EXCEPTION.getCode(),
                                LOGIN_SESSION_INVALIDATE_EXCEPTION.getMessage());
                        response.getWriter().write(jsonResponse);
                    }
                })
                .clearAuthentication(true)
        );
    }


    private void configureAuthorization(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authz -> authz
                .requestMatchers(ignoreAuthUrls).permitAll()
                .anyRequest().authenticated()
        );
    }

    private void configureSessionManagement(HttpSecurity http) throws Exception {
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED));
    }

    // Define CORS configuration
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowedOrigins(Arrays.asList(origins.split(",")));  // Allow all origins
        corsConfiguration.addAllowedHeader("*");  // Allow all headers
        corsConfiguration.addAllowedMethod("*");  // Allow all HTTP methods
        corsConfiguration.setAllowCredentials(true);// Allow cookies to be sent
        source.registerCorsConfiguration("/**", corsConfiguration);
        return source;
    }

}
