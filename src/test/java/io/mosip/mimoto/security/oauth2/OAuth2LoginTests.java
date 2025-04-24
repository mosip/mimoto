package io.mosip.mimoto.security.oauth2;

import io.mosip.mimoto.config.Config;
import io.mosip.mimoto.controller.UsersController;
import io.mosip.mimoto.dbentity.UserMetadata;
import io.mosip.mimoto.exception.OAuth2AuthenticationException;
import io.mosip.mimoto.repository.UserMetadataRepository;
import io.mosip.mimoto.service.LogoutService;
import io.mosip.mimoto.service.WalletService;
import io.mosip.mimoto.util.EncryptionDecryptionUtil;
import io.mosip.mimoto.util.WalletValidator;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
import org.springframework.http.HttpStatus;
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
@Import({UsersController.class, OAuth2AuthenticationSuccessHandler.class, OAuth2AuthenticationFailureHandler.class, HttpSessionOAuth2AuthorizationRequestRepository.class})
@Slf4j
public class OAuth2LoginTests {

    @Value("${mosip.inji.web.url}")
    private String injiWebUrl;

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;

    @Autowired
    private OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;

    @MockBean
    private UserMetadataRepository userMetadataRepository;

    @MockBean
    private LogoutService logoutService;

    @MockBean
    private WalletService walletService;

    @MockBean
    private WalletValidator walletValidator;

    @MockBean
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    @MockBean
    private ClientRegistrationRepository clientRegistrationRepository;

    @MockBean
    private SessionRepository sessionRepository;

    @MockBean
    private OAuth2AuthorizedClientService oAuth2AuthorizedClientService;

    private String providerSubjectId, identityProvider, displayName, profilePictureUrl, email, userId;
    private Timestamp now;
    private UserMetadata userMetadata;

    MockHttpSession mockSession;

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
        mockSession = new MockHttpSession();
    }

    @Test
    public void shouldReturn401OnUnauthenticatedAccessToProtectedEndpoint() throws Exception {
        mockMvc.perform(get("/users/me"))
                .andExpect(status().is4xxClientError());
    }

    @Test
    public void shouldBeAbleToAccessProtectedEndpointWhenUserIsAuthenticatedUsingOAuth2() throws Exception {
        Mockito.when(userMetadataRepository.findByProviderSubjectIdAndIdentityProvider("user123", "google")).thenReturn(Optional.of(userMetadata));
        when(encryptionDecryptionUtil.decrypt(anyString(), any(), any(), any())).thenReturn(displayName, profilePictureUrl, email);
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

        mockMvc.perform(get("/users/me/db")
                        .session(mockSession)
                        .with(oauth2Login().oauth2User(oauth2User)))
                .andExpect(status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.display_name").value("user_123"))
                .andExpect(MockMvcResultMatchers.jsonPath("$.profile_picture_url").value("https://example.com/profile.jpg"))
                .andExpect(MockMvcResultMatchers.jsonPath("$.email").value("user.123@example.com"))
                .andExpect(jsonPath("$.errorCode").doesNotExist())
                .andExpect(jsonPath("$.errorMessage").doesNotExist());
    }

    @Test
    public void shouldThrowExceptionWhenLogoutRequestWasSentForInvalidSession() throws Exception {
        String sessionId = "mockSessionId";
        String encodedSessionId = Base64.getUrlEncoder().encodeToString(sessionId.getBytes());
        Cookie sessionCookie = new Cookie("SESSION", encodedSessionId);
        mockSession.setAttribute("clientRegistrationId", "google");

        doThrow(new OAuth2AuthenticationException("NOT_FOUND",
                "Logout request was sent for an invalid or expired session",
                HttpStatus.NOT_FOUND))
                .when(logoutService).handleLogout(any(HttpServletRequest.class), any(HttpServletResponse.class), eq(sessionRepository));


        mockMvc.perform(post("/logout")
                        .session(mockSession).cookie(sessionCookie))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.errors[0].errorCode").value("user_logout_error"))
                .andExpect(jsonPath("$.errors[0].errorMessage").value("Exception occurred when invalidating the session of a user"));

    }

    @Test
    public void shouldPerformLogoutSuccessfullyForaValidSession() throws Exception {
        String sessionId = "mockSessionId";
        String encodedSessionId = Base64.getUrlEncoder().encodeToString(sessionId.getBytes());
        Cookie sessionCookie = new Cookie("SESSION", encodedSessionId);
        mockSession.setAttribute("clientRegistrationId", "google");
        Session mockSessionFromRepo = Mockito.mock(Session.class);
        when(sessionRepository.findById(sessionId)).thenReturn(mockSessionFromRepo);

        mockMvc.perform(post("/logout")
                        .session(mockSession).cookie(sessionCookie))
                .andExpect(status().isOk());
    }

    @Test
    public void shouldSendTheCustomErrorInRedirectUrlWhenUserDeniesConsentDuringLogin() throws Exception {
        OAuth2AuthorizationRequest authRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://accounts.google.com/o/oauth2/auth")
                .clientId("test-client-id")
                .redirectUri("https://yourapp.com/oauth2/callback/google")
                .scopes(Collections.singleton("profile"))
                .state("test-state")
                .attributes(Map.of(OAuth2ParameterNames.REGISTRATION_ID, "google"))
                .build();

        mockSession.setAttribute(HttpSessionOAuth2AuthorizationRequestRepository.class.getName() + ".AUTHORIZATION_REQUEST", authRequest);

        mockMvc.perform(get("/oauth2/callback/google")
                        .session(mockSession)
                        .param("error", "access_denied")  // Simulating the user clicking "Deny or Cancel" button in the consent
                        .param("state", "test-state"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("https://injiweb.dev1.mosip.net/login?status=error&error_message=Consent+was+denied+to+share+the+details+with+the+application.+Please+give+consent+and+try+again"));
    }

    @Test
    public void shouldThrowTheCustomErrorInRedirectUrlWhenAnyExceptionOccurredDuringLogin() throws Exception {
        //registration_id is not sent in the auth request
        OAuth2AuthorizationRequest authRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://accounts.google.com/o/oauth2/auth")
                .clientId("test-client-id")
                .redirectUri("https://yourapp.com/oauth2/callback/google")
                .scopes(Collections.singleton("profile"))
                .state("test-state")
                .build();

        mockSession.setAttribute(HttpSessionOAuth2AuthorizationRequestRepository.class.getName() + ".AUTHORIZATION_REQUEST", authRequest);

        mockMvc.perform(get("/oauth2/callback/google")
                        .session(mockSession)
                        .param("error", "access_denied")
                        .param("state", "test-state"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl(injiWebUrl + "/login?status=error&error_message=Login+is+failed+due+to+%3A+%5Bclient_registration_not_found%5D+Client+Registration+not+found+with+Id%3A+null"));
    }
}