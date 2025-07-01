package io.mosip.mimoto.security.oauth2;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.config.oauth2.OAuth2ProviderProperties;
import io.mosip.mimoto.dto.ProviderDataConfig;
import io.mosip.mimoto.exception.DecryptionException;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.service.UserMetadataService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CustomOAuth2UserServiceTest {

    @Mock
    private OAuth2ProviderProperties providerProperties;

    @Mock
    private UserMetadataService userMetadataService;

    private CustomOAuth2UserService customOAuth2UserService;

    private ClientRegistration clientRegistration;
    private OAuth2AccessToken accessToken;
    private OAuth2UserRequest oAuth2UserRequest;
    private Map<String, ProviderDataConfig> providersConfig;

    private static class TestableOAuth2UserService extends CustomOAuth2UserService {
        private final OAuth2User testUser;

        public TestableOAuth2UserService(OAuth2ProviderProperties properties, UserMetadataService service, OAuth2User testUser) {
            super(properties, service);
            this.testUser = testUser;
        }

        @Override
        protected OAuth2User loadFromProvider(OAuth2UserRequest userRequest) {
            return testUser;
        }
    }

    @BeforeEach
    void setUp() {
        clientRegistration = ClientRegistration.withRegistrationId("test-provider")
                .clientId("test-client-id")
                .clientSecret("test-client-secret")
                .authorizationUri("https://example.com/oauth/authorize")
                .tokenUri("https://example.com/oauth/token")
                .userInfoUri("https://example.com/oauth/userinfo")
                .userNameAttributeName("sub")
                .clientName("Test Provider")
                .redirectUri("{baseUrl}/oauth2/callback/{registrationId}")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .build();

        accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "test-token",
                Instant.now(),
                Instant.now().plusSeconds(3600)
        );

        oAuth2UserRequest = new OAuth2UserRequest(clientRegistration, accessToken);
        providersConfig = new HashMap<>();
    }

    @Test
    void testLoadUserSuccessfulFlow() throws DecryptionException {
        // Arrange
        Map<String, Object> userAttributes = new HashMap<>();
        userAttributes.put("sub", "test-subject");
        userAttributes.put("name", "Test User");
        userAttributes.put("email", "test@example.com");
        userAttributes.put("phone", "123-456-7890");
        userAttributes.put("picture", "https://example.com/avatar.jpg");

        OAuth2User defaultUser = new DefaultOAuth2User(
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")),
                userAttributes,
                "sub"
        );

        ProviderDataConfig providerConfig = new ProviderDataConfig();
        providerConfig.setUserNameAttribute("sub");
        providerConfig.setNameAttribute("name");
        providerConfig.setEmailAttribute("email");
        providerConfig.setPhoneNumberAttribute("phone");
        providerConfig.setPictureAttribute("picture");

        providersConfig.put("test-provider", providerConfig);
        when(providerProperties.getProvider()).thenReturn(providersConfig);
        when(userMetadataService.updateOrCreateUserMetadata(anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn("test-user-id");

        customOAuth2UserService = new TestableOAuth2UserService(providerProperties, userMetadataService, defaultUser);

        // Act
        OAuth2User actualUser = customOAuth2UserService.loadUser(oAuth2UserRequest);

        // Assert
        assertNotNull(actualUser);
        assertEquals("Test User", actualUser.getAttributes().get("name"));
        assertEquals("test@example.com", actualUser.getAttributes().get("email"));
        assertEquals("123-456-7890", actualUser.getAttributes().get("phone"));
        assertEquals("https://example.com/avatar.jpg", actualUser.getAttributes().get("picture"));
        assertEquals("test-user-id", actualUser.getAttributes().get(SessionKeys.USER_ID));

        verify(userMetadataService).updateOrCreateUserMetadata(
                "test-subject",
                "test-provider",
                "Test User",
                "https://example.com/avatar.jpg",
                "test@example.com"
        );
    }

    @Test
    void testLoadUserWithNestedPictureData() throws DecryptionException {
        // Arrange
        Map<String, Object> pictureMap = new HashMap<>();
        Map<String, Object> dataMap = new HashMap<>();
        dataMap.put("url", "https://example.com/nested.jpg");
        pictureMap.put("data", dataMap);

        Map<String, Object> userAttributes = new HashMap<>();
        userAttributes.put("sub", "nested-subject");
        userAttributes.put("name", "Nested User");
        userAttributes.put("email", "nested@example.com");
        userAttributes.put("phone", "9999999999");
        userAttributes.put("picture", pictureMap);

        OAuth2User nestedPictureUser = new DefaultOAuth2User(
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")),
                userAttributes,
                "sub"
        );

        ProviderDataConfig providerConfig = new ProviderDataConfig();
        providerConfig.setUserNameAttribute("sub");
        providerConfig.setNameAttribute("name");
        providerConfig.setEmailAttribute("email");
        providerConfig.setPhoneNumberAttribute("phone");
        providerConfig.setPictureAttribute("picture");

        providersConfig.put("test-provider", providerConfig);
        when(providerProperties.getProvider()).thenReturn(providersConfig);
        when(userMetadataService.updateOrCreateUserMetadata(anyString(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn("nested-user-id");

        customOAuth2UserService = new TestableOAuth2UserService(providerProperties, userMetadataService, nestedPictureUser);

        // Act
        OAuth2User actualUser = customOAuth2UserService.loadUser(oAuth2UserRequest);

        // Assert
        assertEquals("https://example.com/nested.jpg", actualUser.getAttributes().get("picture"));
        assertEquals("nested-user-id", actualUser.getAttributes().get(SessionKeys.USER_ID));
    }

    @Test
    void testLoadUserThrowsRuntimeExceptionOnDecryptionFailure() throws DecryptionException {
        // Arrange
        Map<String, Object> userAttributes = new HashMap<>();
        userAttributes.put("sub", "error-subject");
        userAttributes.put("name", "Error User");
        userAttributes.put("email", "error@example.com");
        userAttributes.put("phone", "0000000000");
        userAttributes.put("picture", "https://example.com/error.jpg");

        OAuth2User errorUser = new DefaultOAuth2User(
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")),
                userAttributes,
                "sub"
        );

        ProviderDataConfig providerConfig = new ProviderDataConfig();
        providerConfig.setUserNameAttribute("sub");
        providerConfig.setNameAttribute("name");
        providerConfig.setEmailAttribute("email");
        providerConfig.setPhoneNumberAttribute("phone");
        providerConfig.setPictureAttribute("picture");

        providersConfig.put("test-provider", providerConfig);
        when(providerProperties.getProvider()).thenReturn(providersConfig);
        when(userMetadataService.updateOrCreateUserMetadata(any(), any(), any(), any(), any()))
                .thenThrow(new DecryptionException(ErrorConstants.DECRYPTION_FAILED.getErrorCode(), "Decryption failed"));

        customOAuth2UserService = new TestableOAuth2UserService(providerProperties, userMetadataService, errorUser);

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class,
                () -> customOAuth2UserService.loadUser(oAuth2UserRequest));

        assertTrue(exception.getCause() instanceof DecryptionException);
        assertEquals("Metadata update failed", exception.getMessage());
    }

    @Test
    void testLoadUserWithMissingOptionalAttributes() throws DecryptionException {
        // Arrange
        Map<String, Object> userAttributes = new HashMap<>();
        userAttributes.put("sub", "minimal-subject");
        userAttributes.put("name", "Minimal User");

        OAuth2User minimalUser = new DefaultOAuth2User(
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")),
                userAttributes,
                "sub"
        );

        ProviderDataConfig providerConfig = new ProviderDataConfig();
        providerConfig.setUserNameAttribute("sub");
        providerConfig.setNameAttribute("name");
        providerConfig.setEmailAttribute("email");
        providerConfig.setPhoneNumberAttribute("phone");
        providerConfig.setPictureAttribute("picture");

        providersConfig.put("test-provider", providerConfig);
        when(providerProperties.getProvider()).thenReturn(providersConfig);
        when(userMetadataService.updateOrCreateUserMetadata(any(), any(), any(), any(), any()))
                .thenReturn("minimal-user-id");

        customOAuth2UserService = new TestableOAuth2UserService(providerProperties, userMetadataService, minimalUser);

        // Act
        OAuth2User actualUser = customOAuth2UserService.loadUser(oAuth2UserRequest);

        // Assert
        assertEquals("Minimal User", actualUser.getAttributes().get("name"));
        assertNull(actualUser.getAttributes().get("email"));
        assertNull(actualUser.getAttributes().get("phone"));
        assertNull(actualUser.getAttributes().get("picture"));
    }
}
