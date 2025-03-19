package io.mosip.mimoto.security.oauth2;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Component
@Slf4j
public class OAuth2AuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Value("${mosip.inji.web.url}")
    private String injiWebUrl;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
            throws IOException {
        String errorMessage = "";

        if (exception != null) {
            if (exception instanceof OAuth2AuthenticationException) {
                Throwable cause = exception.getCause();
                if (cause instanceof java.net.SocketTimeoutException) {
                    errorMessage = "Timeout while connecting to the IDP for authorization.";
                } else if (cause instanceof java.net.ConnectException) {
                    errorMessage = "Could not connect to the IDP for authorization.";
                } else if (exception.getMessage().contains("access_denied")) {
                    errorMessage = "Access Denied. Please try again.";
                } else {
                    errorMessage = "Login is failed due to: " + exception.getMessage();
                }
            } else {
                errorMessage = "Login is failed due to: " + exception.getMessage();
            }
        }

        String encodedErrorMessage = URLEncoder.encode(errorMessage, StandardCharsets.UTF_8);
        String redirectUrl = injiWebUrl + "/login?status=error&error_message=" + encodedErrorMessage;
        getRedirectStrategy().sendRedirect(request, response, redirectUrl);
    }
}