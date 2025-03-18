package io.mosip.mimoto.security.oauth2;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Component
@Slf4j
public class OAuth2AuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception)
            throws IOException {
        String error = request.getParameter("error");
        String errorMessage;

        if ("access_denied".equals(error)) {
            errorMessage = "Access Denied. Please try again.";
        } else {
            errorMessage = "Authentication failed. Please try again.";
        }

        String encodedErrorMessage = URLEncoder.encode(errorMessage, StandardCharsets.UTF_8);
        String redirectUrl = "http://localhost:3004/login?status=error&error_message=" + encodedErrorMessage;
        getRedirectStrategy().sendRedirect(request, response, redirectUrl);
    }
}