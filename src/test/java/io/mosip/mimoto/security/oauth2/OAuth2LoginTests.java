package io.mosip.mimoto.security.oauth2;

import io.mosip.mimoto.config.Config;
import io.mosip.mimoto.controller.UserController;
import io.mosip.mimoto.dbentity.UserMetadata;
import io.mosip.mimoto.repository.UserMetadataRepository;
import io.mosip.mimoto.service.UserMetadataService;
import io.mosip.mimoto.util.EncryptionDecryptionUtil;
import jakarta.servlet.http.Cookie;
import lombok.extern.slf4j.Slf4j;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
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
@Import({UserController.class, OAuth2AuthenticationSuccessHandler.class, OAuth2AuthenticationFailureHandler.class, HttpSessionOAuth2AuthorizationRequestRepository.class})
@Slf4j
public class OAuth2LoginTests {

    @Value("${mosip.inji.web.url}")
    private String injiWebUrl;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;

    @Autowired
    private OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;

    @MockBean
    private UserMetadataRepository userMetadataRepository;

    @MockBean
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    @MockBean
    private ClientRegistrationRepository clientRegistrationRepository;

    @MockBean
    private SessionRepository sessionRepository;

    @MockBean
    private UserMetadataService userMetadataService;

    @MockBean
    private OAuth2AuthorizedClientService oAuth2AuthorizedClientService;

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

        ClientRegistration googleClient = ClientRegistration.withRegistrationId("google")
                .clientId("test-client-id")
                .clientSecret("test-client-secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://injiweb.dev1.mosip.net/login/oauth2/callback/google")
                .tokenUri("https://oauth2.googleapis.com/token")
                .authorizationUri("https://accounts.google.com/o/oauth2/auth")
                .userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
                .clientName("Google")
                .build();

        when(clientRegistrationRepository.findByRegistrationId("google")).thenReturn(googleClient);
    }

    @Test
    public void shouldBeRedirectedToRedirectEndpointOnUnauthenticatedAccessToProtectedEndpoint() throws Exception {
        mockMvc.perform(get("/secure/user/profile"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl(injiWebUrl+"/login"));
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

    @Test
    public void shouldSendTheCustomErrorInRedirectUrlWhenUserDeniesConsentDuringLogin() throws Exception {
        MockHttpSession mockSession = new MockHttpSession();

        OAuth2AuthorizationRequest authRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://accounts.google.com/o/oauth2/auth")
                .clientId("test-client-id")
                .redirectUri("https://yourapp.com/oauth2/callback/google")
                .scopes(Collections.singleton("profile"))
                .state("test-state")
                .attributes(Map.of(OAuth2ParameterNames.REGISTRATION_ID, "google"))
                .build();

        // Store in session under the expected key
        mockSession.setAttribute(HttpSessionOAuth2AuthorizationRequestRepository.class.getName() + ".AUTHORIZATION_REQUEST", authRequest);

        mockMvc.perform(get("/oauth2/callback/google")
                        .session(mockSession)
                        .param("error", "access_denied")  // Simulating the user clicking "Deny or Cancel" button in the consent
                        .param("state", "test-state")
                        .param("registration_id", "google"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("https://injiweb.dev1.mosip.net/login?status=error&error_message=Consent+was+denied+to+share+the+details+with+the+application.+Please+give+consent+and+try+again"));
    }

    @Test
    public void shouldThrowTheCustomErrorInRedirectUrlWhenAnyExceptionOccurredDuringLogin() throws Exception {
        MockHttpSession mockSession = new MockHttpSession();

        //registration_id is not sent in the auth request
        OAuth2AuthorizationRequest authRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://accounts.google.com/o/oauth2/auth")
                .clientId("test-client-id")
                .redirectUri("https://yourapp.com/oauth2/callback/google")
                .scopes(Collections.singleton("profile"))
                .state("test-state")
                .build();

        // Store in session under the expected key
        mockSession.setAttribute(HttpSessionOAuth2AuthorizationRequestRepository.class.getName() + ".AUTHORIZATION_REQUEST", authRequest);

        mockMvc.perform(get("/oauth2/callback/google")
                        .session(mockSession)
                        .param("error", "access_denied")
                        .param("state", "test-state")
                        .param("registration_id", "google"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl(injiWebUrl+"/login?status=error&error_message=Login+is+failed+due+to+%3A+%5Bclient_registration_not_found%5D+Client+Registration+not+found+with+Id%3A+null"));
    }
}