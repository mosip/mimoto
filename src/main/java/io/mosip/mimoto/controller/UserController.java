package io.mosip.mimoto.controller;

import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.dbentity.UserMetadata;
import io.mosip.mimoto.exception.OAuth2AuthenticationException;
import io.mosip.mimoto.repository.UserMetadataRepository;
import io.mosip.mimoto.util.Utilities;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import static io.mosip.mimoto.exception.PlatformErrorMessages.OAUTH2_AUTHENTICATION_EXCEPTION;

@Slf4j
@RestController
@RequestMapping(value = "/secure/user")
public class UserController {

    @Autowired
    private UserMetadataRepository userMetadataRepository;

    @GetMapping("/profile")
    public ResponseEntity<ResponseWrapper<String>> getUserProfile(Authentication authentication, HttpSession session) {
        try {
            ResponseWrapper<String> responseWrapper = new ResponseWrapper<>();
            if (authentication == null || !authentication.isAuthenticated()) {
                throw new OAuth2AuthenticationException("UNAUTHORIZED", "User is not authenticated", HttpStatus.UNAUTHORIZED);
            }

            String identityProvider = (String) session.getAttribute("clientRegistrationId");
            if (identityProvider.isEmpty()) {
                throw new OAuth2AuthenticationException("BAD_REQUEST", "Identity provider is not available in the received authentication response", HttpStatus.BAD_REQUEST);
            }

            UserMetadata userMetadata = fetchUserMetadata(authentication.getName());
            validateIdentityProvider(userMetadata, identityProvider);

            String userDetails = String.format("{\"displayName\": \"%s\", \"profilePictureUrl\": \"%s\"}",
                    userMetadata.getDisplayName(),
                    userMetadata.getProfilePictureUrl());
            responseWrapper.setResponse(userDetails);
            return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);

        } catch (OAuth2AuthenticationException exception) {
            log.error("Error occurred while retrieving user profile : ", exception);
            return Utilities.handleErrorResponse(exception, OAUTH2_AUTHENTICATION_EXCEPTION.getCode(), exception.getStatus());
        } catch (Exception exception) {
            log.error("Error occurred while retrieving user profile : ", exception);
            return Utilities.handleErrorResponse(exception, OAUTH2_AUTHENTICATION_EXCEPTION.getCode(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private UserMetadata fetchUserMetadata(String providerSubjectId) throws OAuth2AuthenticationException {
        return userMetadataRepository.findByProviderSubjectId(providerSubjectId)
                .orElseThrow(() -> new OAuth2AuthenticationException("NOT_FOUND", "User not found", HttpStatus.NOT_FOUND));
    }

    private void validateIdentityProvider(UserMetadata userMetadata, String identityProvider) throws OAuth2AuthenticationException {
        if (!userMetadata.getIdentityProvider().equals(identityProvider)) {
            throw new OAuth2AuthenticationException("UNAUTHORIZED", "Identity provider mismatch", HttpStatus.UNAUTHORIZED);
        }
    }
}
