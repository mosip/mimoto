package io.mosip.mimoto.security.oauth2;

import io.mosip.mimoto.config.Config;
import io.mosip.mimoto.controller.UserController;
import io.mosip.mimoto.dbentity.UserMetadata;
import io.mosip.mimoto.repository.UserMetadataRepository;
import io.mosip.mimoto.util.EncryptionDecryptionUtil;
import jakarta.servlet.http.Cookie;
import lombok.extern.slf4j.Slf4j;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import java.sql.Timestamp;
import java.util.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oauth2Login;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(SpringRunner.class)
@ContextConfiguration(classes = Config.class)
@WebMvcTest(Config.class)
@AutoConfigureMockMvc
@Import({UserController.class})
@Slf4j
public class OAuth2LoginTests {
    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;

    @MockBean
    private OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;

    @MockBean
    private UserMetadataRepository userMetadataRepository;

    @MockBean
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    @MockBean
    private ClientRegistrationRepository clientRegistrationRepository;

    @MockBean
    private SessionRepository sessionRepository;

    private String providerSubjectId, identityProvider, displayName, profilePictureUrl, email, userId;
    private Timestamp now;
    private UserMetadata userMetadata;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        providerSubjectId = "user123";
        identityProvider = "google";
        displayName = "user_123";
        profilePictureUrl = "https://example.com/profile.jpg";
        email = "user.123@example.com";
        now = new Timestamp(System.currentTimeMillis());
        userId = UUID.randomUUID().toString();

        userMetadata = new UserMetadata();
        userMetadata.setId(userId);
        userMetadata.setProviderSubjectId(providerSubjectId);
        userMetadata.setIdentityProvider(identityProvider);
        userMetadata.setDisplayName(displayName);
        userMetadata.setProfilePictureUrl(profilePictureUrl);
        userMetadata.setEmail(email);
        userMetadata.setCreatedAt(now);
        userMetadata.setUpdatedAt(now);
    }

    @Test
    public void shouldBeRedirectedToRedirectEndpointOnUnauthenticatedAccessToProtectedEndpoint() throws Exception {
        mockMvc.perform(get("/secure/user/profile"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("https://injiweb.dev1.mosip.net/login"));
    }

    @Test
    public void shouldBeAbleToAccessProtectedEndpointWhenUserIsAuthenticatedUsingOAuth2() throws Exception {
        Mockito.when(userMetadataRepository.findByProviderSubjectIdAndIdentityProvider("user123", "google")).thenReturn(Optional.of(userMetadata));
        when(encryptionDecryptionUtil.decrypt(anyString(), any(), any(), any())).thenReturn(displayName, profilePictureUrl, email);
        MockHttpSession mockSession = new MockHttpSession();
        mockSession.setAttribute("clientRegistrationId", "google");

        // Create a mock OAuth2User with the necessary attributes, including the name.
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("sub", "user123");
        attributes.put("name", "user_123");
        OAuth2User oauth2User = new DefaultOAuth2User(Collections.emptyList(), attributes, "sub");

        // Create an OAuth2AuthenticationToken.
        OAuth2AuthenticationToken authenticationToken = new OAuth2AuthenticationToken(
                oauth2User,
                Collections.emptyList(),
                "google"
        );

        // Set the authentication token in the security context.
        SecurityContext securityContext = SecurityContextHolder.getContext();
        securityContext.setAuthentication(authenticationToken);

        mockMvc.perform(get("/secure/user/profile")
                        .session(mockSession)
                        .with(oauth2Login().oauth2User(oauth2User)))
                .andExpect(status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.response.display_name").value("user_123"))
                .andExpect(MockMvcResultMatchers.jsonPath("$.response.profile_picture_url").value("https://example.com/profile.jpg"))
                .andExpect(MockMvcResultMatchers.jsonPath("$.response.email").value("user.123@example.com"))
                .andExpect(jsonPath("$.errors").isArray())
                .andExpect(jsonPath("$.errors").isEmpty());
    }

    @Test
    public void shouldThrowExceptionWhenLogoutRequestWasSentForInvalidSession() throws Exception {
        MockHttpSession mockSession = new MockHttpSession();
        String sessionId = "mockSessionId";
        String encodedSessionId = Base64.getUrlEncoder().encodeToString(sessionId.getBytes());
        Cookie sessionCookie = new Cookie("SESSION", encodedSessionId);
        mockSession.setAttribute("clientRegistrationId", "google");
        when(sessionRepository.findById(sessionId)).thenReturn(null);

        mockMvc.perform(post("/logout")
                        .session(mockSession).cookie(sessionCookie))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.errors[0].errorCode").value("NOT_FOUND"))
                .andExpect(jsonPath("$.errors[0].errorMessage").value("Logout request was sent for an invalid or expired session"));

        verify(sessionRepository, times(1)).findById(sessionId);
        verify(sessionRepository, never()).deleteById(sessionId);
    }

    @Test
    public void shouldPerformLogoutSuccessfullyForaValidSession() throws Exception {
        MockHttpSession mockSession = new MockHttpSession();
        String sessionId = "mockSessionId";
        String encodedSessionId = Base64.getUrlEncoder().encodeToString(sessionId.getBytes());
        Cookie sessionCookie = new Cookie("SESSION", encodedSessionId);
        mockSession.setAttribute("clientRegistrationId", "google");
        Session mockSessionFromRepo = Mockito.mock(Session.class);
        when(sessionRepository.findById(sessionId)).thenReturn(mockSessionFromRepo);

        mockMvc.perform(post("/logout")
                        .session(mockSession).cookie(sessionCookie))
                .andExpect(status().isOk());

        verify(sessionRepository, times(1)).findById(sessionId);
        verify(sessionRepository, times(1)).deleteById(sessionId);
    }
}