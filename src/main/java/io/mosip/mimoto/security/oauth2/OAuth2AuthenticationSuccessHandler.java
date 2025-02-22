package io.mosip.mimoto.security.oauth2;

import io.mosip.mimoto.service.UserMetadataService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    @Autowired
    private UserMetadataService userMetadataService;

    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OAuth2AuthenticationToken oauth2Token = (OAuth2AuthenticationToken) authentication;
        OAuth2User oAuth2User = oauth2Token.getPrincipal();
        HttpSession session = request.getSession();
        // Storing clientRegistrationId in the Redis session to verify it against the one in user metadata during profile retrieval
        String clientRegistrationId = oauth2Token.getAuthorizedClientRegistrationId();
        session.setAttribute("clientRegistrationId", clientRegistrationId);

        // Extracting OAuth2 user information
        String providerSubjectId = oAuth2User.getAttribute("sub");
        String identityProvider = oauth2Token.getAuthorizedClientRegistrationId();
        String displayName = oAuth2User.getAttribute("name");
        String profilePictureUrl = oAuth2User.getAttribute("picture");
        String email = oAuth2User.getAttribute("email");

        OAuth2AuthorizedClient authorizedClient = authorizedClientService
                .loadAuthorizedClient(oauth2Token.getAuthorizedClientRegistrationId(), authentication.getName());

        String accessToken = authorizedClient.getAccessToken().getTokenValue();
        String refreshToken = authorizedClient.getRefreshToken().getTokenValue();
        session.setAttribute("accessToken", accessToken);
        session.setAttribute("refreshToken", refreshToken);

        // Call the service to update or insert the user metadata in the database
        userMetadataService.updateOrInsertUserMetadata(providerSubjectId, identityProvider, displayName, profilePictureUrl, email);

        response.sendRedirect("http://localhost:3004/login?status=success");

    }
}
