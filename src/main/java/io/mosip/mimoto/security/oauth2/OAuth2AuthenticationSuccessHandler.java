package io.mosip.mimoto.security.oauth2;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.mimoto.UserMetadataDTO;
import io.mosip.mimoto.service.UserMetadataService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@Slf4j
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    @Autowired
    private UserMetadataService userMetadataService;

    @Value("${mosip.inji.web.url}")
    private String injiWebUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OAuth2AuthenticationToken oauth2Token = (OAuth2AuthenticationToken) authentication;
        OAuth2User oAuth2User = oauth2Token.getPrincipal();
        HttpSession session = request.getSession(false);
        if (session == null) {
            log.error("Session not available");
            throw new ServletException("Session not available");
        }

        // Storing clientRegistrationId in the Redis session to verify it against the one in user metadata during profile retrieval
        String clientRegistrationId = oauth2Token.getAuthorizedClientRegistrationId();
        session.setAttribute("clientRegistrationId", clientRegistrationId);

        // Extracting OAuth2 user information
        String providerSubjectId = oAuth2User.getAttribute("sub");
        String identityProvider = oauth2Token.getAuthorizedClientRegistrationId();
        String displayName = oAuth2User.getAttribute("name");
        String profilePictureUrl = oAuth2User.getAttribute("picture");
        String email = oAuth2User.getAttribute("email");

        // Call the service to update or insert the user metadata in the database

        String userId = userMetadataService.updateOrInsertUserMetadata(providerSubjectId, identityProvider, displayName, profilePictureUrl, email);
        UserMetadataDTO userMetadataDTO = new UserMetadataDTO(displayName,
                    profilePictureUrl,
                    email);
        session.setAttribute(SessionKeys.USER_METADATA, userMetadataDTO);
        session.setAttribute(SessionKeys.USER_ID, userId);
        response.sendRedirect(injiWebUrl + "/login?status=success");

    }
}
