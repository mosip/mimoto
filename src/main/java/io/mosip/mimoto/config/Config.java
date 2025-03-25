package io.mosip.mimoto.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.exception.OAuth2AuthenticationException;
import io.mosip.mimoto.security.oauth2.OAuth2AuthenticationFailureHandler;
import io.mosip.mimoto.security.oauth2.OAuth2AuthenticationSuccessHandler;
import io.mosip.mimoto.util.Utilities;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
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
import org.springframework.security.web.SecurityFilterChain;
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


    @Value("${mosip.inji.web.url}")
    private String injiWebUrl;

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

        return http.build();

    }

    private void setupOauth2Config(HttpSecurity http, SessionRepository sessionRepository) throws Exception {
        http
                .oauth2Login((oauth2Login) -> oauth2Login.loginPage(injiWebUrl + "/login")
                        .authorizationEndpoint(authorization -> authorization.baseUri("/oauth2/authorize")
                        )
                        .redirectionEndpoint(redirect -> redirect.baseUri("/oauth2/callback/*"))
                        .successHandler(oAuth2AuthenticationSuccessHandler)
                        .failureHandler(oAuth2AuthenticationFailureHandler)
                )
                .logout(logout -> logout
                        .invalidateHttpSession(false)
                        .clearAuthentication(false)
                        .logoutUrl("/logout")
                        .logoutSuccessHandler((request, response, authentication) -> {
                            try {
                                Cookie[] cookies = request.getCookies();
                                if (cookies != null) {
                                    for (Cookie cookie : cookies) {
                                        if ("SESSION".equals(cookie.getName())) {
                                            String encodedSessionId = cookie.getValue();
                                            String sessionId = new String(Base64.getUrlDecoder().decode(encodedSessionId));
                                            if (sessionRepository.findById(sessionId) != null) {
                                                sessionRepository.deleteById(sessionId);
                                            } else {
                                                throw new OAuth2AuthenticationException("NOT_FOUND", "Logout request was sent for an invalid or expired session", HttpStatus.NOT_FOUND);
                                            }
                                        }
                                    }
                                }

                                HttpSession session = request.getSession(false);
                                if (session != null) {
                                    session.invalidate(); // Explicitly invalidate the session
                                }
                            } catch (OAuth2AuthenticationException exception) {
                                ResponseEntity<ResponseWrapper<String>> responseEntity = Utilities.handleErrorResponse(exception, LOGIN_SESSION_INVALIDATE_EXCEPTION.getCode(), exception.getStatus(), null);
                                response.setStatus(responseEntity.getStatusCodeValue());
                                response.setContentType("application/json");

                                ObjectMapper objectMapper = new ObjectMapper();
                                String jsonResponse = objectMapper.writeValueAsString(responseEntity.getBody());
                                response.getWriter().write(jsonResponse);
                            } catch (Exception exception) {
                                ResponseEntity<ResponseWrapper<String>> responseEntity = Utilities.handleErrorResponse(exception, LOGIN_SESSION_INVALIDATE_EXCEPTION.getCode(), HttpStatus.INTERNAL_SERVER_ERROR, null);
                                response.setStatus(responseEntity.getStatusCodeValue());
                                response.setContentType("application/json");

                                ObjectMapper objectMapper = new ObjectMapper();
                                String jsonResponse = objectMapper.writeValueAsString(responseEntity.getBody());
                                response.getWriter().write(jsonResponse);
                            }
                        })
                        .clearAuthentication(true)
                )
                .authorizeHttpRequests(authz -> authz
                        // make existing endpoints public
                        .requestMatchers("/safetynet/**", "/allProperties", "/credentials/**",
                                "/credentialshare/**","/binding-otp","/wallet-binding","/get-token/**",
                                "/issuers","/issuers/**","/authorize","/req/otp","/vid","/req/auth/**",
                                "/req/individualId/otp","/aid/get-individual-id","/session/status",
                                "/verifiers").permitAll()
                        // Apply the default authorization rule to all other requests, ensuring authentication is required.
                        .anyRequest().authenticated()
                ).sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED));
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
