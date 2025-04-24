package io.mosip.mimoto.security.oauth2;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.mimoto.UserMetadataDTO;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.service.UserMetadataService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.io.IOException;
import java.lang.reflect.Field;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class OAuth2AuthenticationSuccessHandlerTest {

    @InjectMocks
    private OAuth2AuthenticationSuccessHandler successHandler;

    @Mock
    private UserMetadataService userMetadataService;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private HttpSession session;

    @Mock
    private OAuth2AuthenticationToken oauth2Token;

    @Mock
    private OAuth2User oauth2User;

    private static final String INJI_WEB_URL = "https://example.com";
    private static final String CLIENT_REGISTRATION_ID = "google";
    private static final String PROVIDER_SUBJECT_ID = "sub123";
    private static final String DISPLAY_NAME = "John Doe";
    private static final String PROFILE_PICTURE_URL = "https://example.com/profile.jpg";
    private static final String EMAIL = "john.doe@example.com";
    private static final String USER_ID = "user456";

    @Before
    public void setUp() throws Exception {
        // Set the injiWebUrl field using reflection to simulate @Value injection
        Field injiWebUrlField = OAuth2AuthenticationSuccessHandler.class.getDeclaredField("injiWebUrl");
        injiWebUrlField.setAccessible(true);
        injiWebUrlField.set(successHandler, INJI_WEB_URL);

        // Mock session behavior
        when(request.getSession(false)).thenReturn(session);
    }

    @Test
    public void onAuthenticationSuccessSetsSessionAttributesAndRedirects() throws IOException, ServletException {
        // Arrange
        when(oauth2Token.getAuthorizedClientRegistrationId()).thenReturn(CLIENT_REGISTRATION_ID);
        when(oauth2Token.getPrincipal()).thenReturn(oauth2User);
        when(oauth2User.getAttribute("sub")).thenReturn(PROVIDER_SUBJECT_ID);
        when(oauth2User.getAttribute("name")).thenReturn(DISPLAY_NAME);
        when(oauth2User.getAttribute("picture")).thenReturn(PROFILE_PICTURE_URL);
        when(oauth2User.getAttribute("email")).thenReturn(EMAIL);
        when(userMetadataService.updateOrInsertUserMetadata(
                eq(PROVIDER_SUBJECT_ID), eq(CLIENT_REGISTRATION_ID), eq(DISPLAY_NAME),
                eq(PROFILE_PICTURE_URL), eq(EMAIL)))
                .thenReturn(USER_ID);

        // Act
        successHandler.onAuthenticationSuccess(request, response, oauth2Token);

        // Assert
        verify(session).setAttribute(eq("clientRegistrationId"), eq(CLIENT_REGISTRATION_ID));
        verify(session).setAttribute(eq(SessionKeys.USER_ID), eq(USER_ID));
        verify(response).sendRedirect(eq(INJI_WEB_URL + "/login?status=success"));
        verify(userMetadataService).updateOrInsertUserMetadata(
                eq(PROVIDER_SUBJECT_ID), eq(CLIENT_REGISTRATION_ID), eq(DISPLAY_NAME),
                eq(PROFILE_PICTURE_URL), eq(EMAIL));

        // Verify UserMetadataDTO using ArgumentCaptor
        ArgumentCaptor<UserMetadataDTO> captor = ArgumentCaptor.forClass(UserMetadataDTO.class);
        verify(session).setAttribute(eq(SessionKeys.USER_METADATA), captor.capture());
        UserMetadataDTO userMetadataDTO = captor.getValue();
        assertEquals(DISPLAY_NAME, userMetadataDTO.getDisplayName());
        assertEquals(PROFILE_PICTURE_URL, userMetadataDTO.getProfilePictureUrl());
        assertEquals(EMAIL, userMetadataDTO.getEmail());
    }

    @Test
    public void onAuthenticationSuccessWithNullAttributesSetsSessionAttributesAndRedirects() throws IOException, ServletException {
        // Arrange
        when(oauth2Token.getAuthorizedClientRegistrationId()).thenReturn(CLIENT_REGISTRATION_ID);
        when(oauth2Token.getPrincipal()).thenReturn(oauth2User);
        when(oauth2User.getAttribute("sub")).thenReturn(PROVIDER_SUBJECT_ID);
        when(oauth2User.getAttribute("name")).thenReturn(null);
        when(oauth2User.getAttribute("picture")).thenReturn(null);
        when(oauth2User.getAttribute("email")).thenReturn(null);
        when(userMetadataService.updateOrInsertUserMetadata(
                eq(PROVIDER_SUBJECT_ID), eq(CLIENT_REGISTRATION_ID), isNull(),
                isNull(), isNull()))
                .thenReturn(USER_ID);

        // Act
        successHandler.onAuthenticationSuccess(request, response, oauth2Token);

        // Assert
        verify(session).setAttribute(eq("clientRegistrationId"), eq(CLIENT_REGISTRATION_ID));
        verify(session).setAttribute(eq(SessionKeys.USER_ID), eq(USER_ID));
        verify(response).sendRedirect(eq(INJI_WEB_URL + "/login?status=success"));
        verify(userMetadataService).updateOrInsertUserMetadata(
                eq(PROVIDER_SUBJECT_ID), eq(CLIENT_REGISTRATION_ID), isNull(),
                isNull(), isNull());

        // Verify UserMetadataDTO using ArgumentCaptor
        ArgumentCaptor<UserMetadataDTO> captor = ArgumentCaptor.forClass(UserMetadataDTO.class);
        verify(session).setAttribute(eq(SessionKeys.USER_METADATA), captor.capture());
        UserMetadataDTO userMetadataDTO = captor.getValue();
        assertNull(userMetadataDTO.getDisplayName());
        assertNull(userMetadataDTO.getProfilePictureUrl());
        assertNull(userMetadataDTO.getEmail());
    }

    @Test
    public void onAuthenticationSuccessWithNullSessionThrowsServletException() throws IOException {
        // Arrange
        when(request.getSession(false)).thenReturn(null);

        // Act & Assert
        try {
            successHandler.onAuthenticationSuccess(request, response, oauth2Token);
            fail("Expected ServletException");
        } catch (ServletException e) {
            assertEquals("Session not available", e.getMessage());
        }
        verifyNoInteractions(userMetadataService, session);
        verify(response, never()).sendRedirect(anyString());
    }

    @Test
    public void onAuthenticationSuccessWithServiceFailureThrowsIOException() throws IOException, ServletException {
        // Arrange
        when(oauth2Token.getAuthorizedClientRegistrationId()).thenReturn(CLIENT_REGISTRATION_ID);
        when(oauth2Token.getPrincipal()).thenReturn(oauth2User);
        when(oauth2User.getAttribute("sub")).thenReturn(PROVIDER_SUBJECT_ID);
        when(oauth2User.getAttribute("name")).thenReturn(DISPLAY_NAME);
        when(oauth2User.getAttribute("picture")).thenReturn(PROFILE_PICTURE_URL);
        when(oauth2User.getAttribute("email")).thenReturn(EMAIL);
        when(userMetadataService.updateOrInsertUserMetadata(
                eq(PROVIDER_SUBJECT_ID), eq(CLIENT_REGISTRATION_ID), eq(DISPLAY_NAME),
                eq(PROFILE_PICTURE_URL), eq(EMAIL)))
                .thenThrow(new RuntimeException("Service failure"));

        // Act & Assert
        try {
            successHandler.onAuthenticationSuccess(request, response, oauth2Token);
            fail("Expected IOException");
        } catch (RuntimeException e) {
            assertEquals("Service failure", e.getMessage());
        }
        verify(session).setAttribute(eq("clientRegistrationId"), eq(CLIENT_REGISTRATION_ID));
        verify(userMetadataService).updateOrInsertUserMetadata(
                eq(PROVIDER_SUBJECT_ID), eq(CLIENT_REGISTRATION_ID), eq(DISPLAY_NAME),
                eq(PROFILE_PICTURE_URL), eq(EMAIL));
        verify(session, never()).setAttribute(eq(SessionKeys.USER_METADATA), any());
        verify(session, never()).setAttribute(eq(SessionKeys.USER_ID), any());
        verify(response, never()).sendRedirect(anyString());
    }
}