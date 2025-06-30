package io.mosip.mimoto.security.oauth2;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.config.oauth2.OAuth2ProviderProperties;
import io.mosip.mimoto.dto.ProviderDataConfig;
import io.mosip.mimoto.exception.DecryptionException;
import io.mosip.mimoto.service.UserMetadataService;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

/**
 * Custom implementation of the {@link DefaultOAuth2UserService} to handle
 * user information retrieval and processing for OAuth2 authentication.
 *
 * This service customizes the loading of user details from an OAuth2 provider
 * by enriching the user attributes, updating user metadata, and handling
 * provider-specific configurations.
 */
@Service
@Slf4j
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final Map<String, ProviderDataConfig> providers;
    private final UserMetadataService userMetadataService;

    public CustomOAuth2UserService(OAuth2ProviderProperties providerProperties,
                                   UserMetadataService userMetadataService) {
        this.providers = providerProperties.getProvider();
        this.userMetadataService = userMetadataService;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) {
        OAuth2User oAuth2User = loadFromProvider(userRequest);
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        ProviderDataConfig provider = getProviderConfig(registrationId);

        Map<String, Object> attributes = extractAttributes(oAuth2User, provider);
        String userId = updateUserMetadata(attributes, provider, registrationId);
        enrichAttributes(attributes, userId);

        String userNameAttribute = StringUtils.defaultIfBlank(provider.getUserNameAttribute(), "sub");
        return new DefaultOAuth2User(oAuth2User.getAuthorities(), attributes, userNameAttribute);
    }

    private ProviderDataConfig getProviderConfig(String registrationId) {
        ProviderDataConfig provider = providers.get(registrationId);
        if (provider == null) {
            log.error("Missing OAuth2 provider config for: {}", registrationId);
            throw new IllegalArgumentException("Missing OAuth2 provider config for: " + registrationId);
        }
        return provider;
    }

    private Map<String, Object> extractAttributes(OAuth2User oAuth2User, ProviderDataConfig provider) {
        Map<String, Object> attributes = new HashMap<>(oAuth2User.getAttributes());
        attributes.put("name", safeGet(attributes, provider.getNameAttribute()));
        attributes.put("email", safeGet(attributes, provider.getEmailAttribute()));
        attributes.put("phone", safeGet(attributes, provider.getPhoneNumberAttribute()));
        attributes.put("picture", extractProfilePicture(attributes, provider.getPictureAttribute()));
        return attributes;
    }

    private String extractProfilePicture(Map<String, Object> attributes, String pictureAttribute) {
        if (StringUtils.isBlank(pictureAttribute) || !attributes.containsKey(pictureAttribute)) {
            return null;
        }

        Object picture = attributes.get(pictureAttribute);
        if (picture instanceof Map<?, ?> picMap) {
            Object data = picMap.get("data");
            if (data instanceof Map<?, ?> dataMap) {
                Object url = dataMap.get("url");
                return url != null ? url.toString() : null;
            }
        } else if (picture instanceof String picUrl) {
            return picUrl;
        }

        return null;
    }

    private String updateUserMetadata(Map<String, Object> attributes, ProviderDataConfig provider, String registrationId) {
        String providerSubjectId = safeGet(attributes, StringUtils.defaultIfBlank(provider.getUserNameAttribute(), "sub"));
        try {
            return userMetadataService.updateOrInsertUserMetadata(
                    providerSubjectId,
                    registrationId,
                    safeGet(attributes, "name"),
                    safeGet(attributes, "picture"),
                    safeGet(attributes, "email")
            );
        } catch (DecryptionException e) {
            log.error("Error updating user metadata", e);
            throw new RuntimeException("Metadata update failed", e);
        }
    }

    private void enrichAttributes(Map<String, Object> attributes, String userId) {
        attributes.put(SessionKeys.USER_ID, userId);
    }

    private String safeGet(Map<String, Object> attributes, String key) {
        if (StringUtils.isBlank(key)) {
            return null;
        }
        Object value = attributes.get(key);
        if (value == null) {
            return null;
        }
        return value.toString();
    }

    protected OAuth2User loadFromProvider(OAuth2UserRequest userRequest) {
        return super.loadUser(userRequest);
    }
}
