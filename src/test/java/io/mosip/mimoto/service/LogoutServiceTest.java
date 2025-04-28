package io.mosip.mimoto.service;

import io.mosip.mimoto.exception.OAuth2AuthenticationException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class LogoutServiceTest {

    @InjectMocks
    private LogoutService logoutService;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private SessionRepository sessionRepository;

    @Mock
    private HttpSession session;

    @Mock
    private Session springSession;

    private String sessionId = "test-session-id";
    private String encodedSessionId;

    @BeforeEach
    public void setup() {
        encodedSessionId = Base64.getUrlEncoder().encodeToString(sessionId.getBytes());
    }

    @Test
    void shouldSuccessfullyHandleLogoutWithValidSessionCookieAndSession() throws OAuth2AuthenticationException {
        // Arrange
        Cookie sessionCookie = new Cookie("SESSION", encodedSessionId);
        when(request.getCookies()).thenReturn(new Cookie[]{sessionCookie});
        when(sessionRepository.findById(sessionId)).thenReturn(springSession);
        when(request.getSession(false)).thenReturn(session);

        // Act
        logoutService.handleLogout(request, response, sessionRepository);

        // Assert
        verify(sessionRepository).findById(sessionId);
        verify(sessionRepository).deleteById(sessionId);
        verify(session).invalidate();
        verifyNoInteractions(response);
    }

    @Test
    void shouldThrowOAuth2AuthenticationExceptionForInvalidSessionId() {
        // Arrange
        Cookie sessionCookie = new Cookie("SESSION", encodedSessionId);
        when(request.getCookies()).thenReturn(new Cookie[]{sessionCookie});
        when(sessionRepository.findById(sessionId)).thenReturn(null);

        // Act & Assert
        OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class,
                () -> logoutService.handleLogout(request, response, sessionRepository));

        assertEquals("NOT_FOUND", exception.getErrorCode());
        assertEquals("NOT_FOUND --> Logout request was sent for an invalid or expired session", exception.getMessage());
        assertEquals(HttpStatus.NOT_FOUND, exception.getStatus());
        verify(sessionRepository).findById(sessionId);
        verify(sessionRepository, never()).deleteById(anyString());
        verify(request, never()).getSession(false);
        verifyNoInteractions(response, session);
    }

    @Test
    void shouldHandleLogoutWithNoSessionCookie() throws OAuth2AuthenticationException {
        // Arrange
        when(request.getCookies()).thenReturn(new Cookie[]{new Cookie("OTHER_COOKIE", "value")});
        when(request.getSession(false)).thenReturn(session);

        // Act
        logoutService.handleLogout(request, response, sessionRepository);

        // Assert
        verify(sessionRepository, never()).findById(anyString());
        verify(sessionRepository, never()).deleteById(anyString());
        verify(session).invalidate();
        verifyNoInteractions(response);
    }

    @Test
    void shouldHandleLogoutWithNullCookies() throws OAuth2AuthenticationException {
        // Arrange
        when(request.getCookies()).thenReturn(null);
        when(request.getSession(false)).thenReturn(session);

        // Act
        logoutService.handleLogout(request, response, sessionRepository);

        // Assert
        verify(sessionRepository, never()).findById(anyString());
        verify(sessionRepository, never()).deleteById(anyString());
        verify(session).invalidate();
        verifyNoInteractions(response);
    }

    @Test
    void shouldHandleLogoutWithNoHttpSession() throws OAuth2AuthenticationException {
        // Arrange
        Cookie sessionCookie = new Cookie("SESSION", encodedSessionId);
        when(request.getCookies()).thenReturn(new Cookie[]{sessionCookie});
        when(sessionRepository.findById(sessionId)).thenReturn(springSession);
        when(request.getSession(false)).thenReturn(null);

        // Act
        logoutService.handleLogout(request, response, sessionRepository);

        // Assert
        verify(sessionRepository).findById(sessionId);
        verify(sessionRepository).deleteById(sessionId);
        verify(request).getSession(false);
        verifyNoInteractions(session, response);
    }

    @Test
    void shouldHandleLogoutWithEmptyCookiesArray() throws OAuth2AuthenticationException {
        // Arrange
        when(request.getCookies()).thenReturn(new Cookie[]{});
        when(request.getSession(false)).thenReturn(session);

        // Act
        logoutService.handleLogout(request, response, sessionRepository);

        // Assert
        verify(sessionRepository, never()).findById(anyString());
        verify(sessionRepository, never()).deleteById(anyString());
        verify(session).invalidate();
        verifyNoInteractions(response);
    }

    @Test
    void shouldThrowOAuth2AuthenticationExceptionForInvalidBase64SessionId() {
        // Arrange
        Cookie sessionCookie = new Cookie("SESSION", "invalid-base64");
        when(request.getCookies()).thenReturn(new Cookie[]{sessionCookie});

        // Act & Assert
        assertThrows(OAuth2AuthenticationException.class,
                () -> logoutService.handleLogout(request, response, sessionRepository));

        verify(sessionRepository, never()).deleteById(anyString());
        verify(request, never()).getSession(false);
        verifyNoInteractions(response, session);
    }

    @Test
    void shouldHandleMultipleCookiesWithValidSessionCookie() throws OAuth2AuthenticationException {
        // Arrange
        Cookie sessionCookie = new Cookie("SESSION", encodedSessionId);
        Cookie otherCookie = new Cookie("OTHER_COOKIE", "value");
        when(request.getCookies()).thenReturn(new Cookie[]{otherCookie, sessionCookie});
        when(sessionRepository.findById(sessionId)).thenReturn(springSession);
        when(request.getSession(false)).thenReturn(session);

        // Act
        logoutService.handleLogout(request, response, sessionRepository);

        // Assert
        verify(sessionRepository).findById(sessionId);
        verify(sessionRepository).deleteById(sessionId);
        verify(session).invalidate();
        verifyNoInteractions(response);
    }
}