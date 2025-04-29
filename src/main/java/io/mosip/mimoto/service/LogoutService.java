package io.mosip.mimoto.service;

import io.mosip.mimoto.exception.OAuth2AuthenticationException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Service;

import java.util.Base64;

@Service
@Slf4j
public class LogoutService {

    public void handleLogout(HttpServletRequest request, HttpServletResponse response, SessionRepository sessionRepository) throws OAuth2AuthenticationException {

        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("SESSION".equals(cookie.getName())) {
                    String encodedSessionId = cookie.getValue();
                    String sessionId = new String(Base64.getUrlDecoder().decode(encodedSessionId));
                    if (sessionRepository.findById(sessionId) != null) {
                        sessionRepository.deleteById(sessionId);
                    } else {
                        throw new OAuth2AuthenticationException("NOT_FOUND",
                                "Logout request was sent for an invalid or expired session",
                                HttpStatus.NOT_FOUND);
                    }
                }
            }
        }

        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }

    }


}
