package io.mosip.mimoto.security.oauth2;

import io.mosip.mimoto.config.Config;
import io.mosip.mimoto.controller.UserController;
import io.mosip.mimoto.repository.UserMetadataRepository;
import io.mosip.mimoto.service.UserMetadataService;
import io.mosip.mimoto.service.WalletService;
import io.mosip.mimoto.util.EncryptionDecryptionUtil;
import io.mosip.mimoto.util.WalletValidator;
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
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.session.SessionRepository;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import java.util.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(SpringRunner.class)
@ContextConfiguration(classes = Config.class)
@WebMvcTest(Config.class)
@AutoConfigureMockMvc
@Import({UserController.class, OAuth2AuthenticationSuccessHandler.class})
@Slf4j
public class OAuth2AuthenticationSuccessHandlerTest {
    @Autowired
    private MockMvc mockMvc;
    @MockBean
    private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;

    @MockBean
    private OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;

    @MockBean
    private SessionRepository sessionRepository;

    @MockBean
    private UserMetadataRepository userMetadataRepository;

    @MockBean
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    @MockBean
    private WalletService walletService;

    @MockBean
    private WalletValidator walletValidator;

    @MockBean
    private OAuth2AuthorizedClientService oAuth2AuthorizedClientService;

    @MockBean
    private ClientRegistrationRepository clientRegistrationRepository;

    @MockBean
    private OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService;

    @MockBean
    private UserMetadataService userMetadataService;

    private String providerSubjectId, identityProvider, displayName, profilePictureUrl, email, userId;

    MockHttpSession mockSession;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        providerSubjectId = "123456789";
        identityProvider = "google";
        displayName = "user_123";
        profilePictureUrl = "https://example.com/profile.jpg";
        email = "user.123@example.com";
        userId = UUID.randomUUID().toString();

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

        OAuth2AuthorizationCodeGrantRequest grantRequest = Mockito.any();
        OAuth2AccessTokenResponse tokenResponse = OAuth2AccessTokenResponse.withToken("mock-access-token")
                .tokenType(OAuth2AccessToken.TokenType.BEARER)
                .expiresIn(3600)
                .build();

        when(accessTokenResponseClient.getTokenResponse(grantRequest)).thenReturn(tokenResponse);
        OAuth2User mockOAuth2User = new DefaultOAuth2User(
                Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")),
                Map.of(
                        "sub", providerSubjectId,
                        "name", displayName,
                        "email", email,
                        "picture", profilePictureUrl
                ),
                "sub"
        );
        when(oauth2UserService.loadUser(any(OAuth2UserRequest.class)))
                .thenReturn(mockOAuth2User);

        OAuth2AuthorizationRequest authRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://accounts.google.com/o/oauth2/auth")
                .clientId("test-client-id")
                .redirectUri("https://yourapp.com/oauth2/callback/google")
                .scopes(Collections.singleton("profile"))
                .state("test-state")
                .attributes(Map.of(OAuth2ParameterNames.REGISTRATION_ID, "google"))
                .build();

        mockSession = new MockHttpSession();
        mockSession.setAttribute(HttpSessionOAuth2AuthorizationRequestRepository.class.getName() + ".AUTHORIZATION_REQUEST", authRequest);
    }

    @Test
    public void shouldReturnRedirectUrlWithSuccessStatusQueryParamIfLoginIsSuccessful() throws Exception {
        mockMvc.perform(get("/oauth2/callback/google")
                        .session(mockSession)
                        .param("code", "test-authorization-code")
                        .param("state", "test-state"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("https://injiweb.dev1.mosip.net/login?status=success"));
    }

    @Test
    public void shouldSendCustomErrorInRedirectUrlWhenLoginIsSuccessfulButAnErrorOccurredInAuthenticationSuccessHandler() throws Exception {
        when(userMetadataService.updateOrInsertUserMetadata(providerSubjectId, identityProvider, displayName, profilePictureUrl,
                email)).thenThrow(new RuntimeException("Failed to store the user metadata"));

        mockMvc.perform(get("/oauth2/callback/google")
                        .session(mockSession)
                        .param("code", "test-authorization-code")
                        .param("state", "test-state"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("https://injiweb.dev1.mosip.net/login?status=error&error_code=RESIDENT-APP-048&error_message=Failed+to+store+the+User+metadata+into+database"));
    }

    @Test
    public void shouldSendCustomErrorInRedirectUrlWhenLoginIsSuccessfulButDatabaseIsNotConnectedToStoreUserData() throws Exception {
        when(userMetadataService.updateOrInsertUserMetadata(providerSubjectId, identityProvider, displayName, profilePictureUrl,
                email)).thenThrow(new DataAccessResourceFailureException("Failed to connect to the database"));

        mockMvc.perform(get("/oauth2/callback/google")
                        .session(mockSession)
                        .param("code", "test-authorization-code")
                        .param("state", "test-state"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("https://injiweb.dev1.mosip.net/login?status=error&error_code=RESIDENT-APP-047&error_message=Failed+to+connect+to+the+shared+database"));
    }
}

