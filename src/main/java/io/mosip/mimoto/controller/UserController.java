package io.mosip.mimoto.controller;

import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.dbentity.UserMetadata;
import io.mosip.mimoto.exception.OAuth2AuthenticationException;
import io.mosip.mimoto.repository.UserMetadataRepository;
import io.mosip.mimoto.util.EncryptionDecryptionUtil;
import io.mosip.mimoto.util.Utilities;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import static io.mosip.mimoto.exception.PlatformErrorMessages.*;

@Slf4j
@RestController
@RequestMapping(value = "/secure/user")
public class UserController {

    @Autowired
    private UserMetadataRepository userMetadataRepository;

    @Autowired
    private EncryptionDecryptionUtil encryptionDecryptionUtill;

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
                    encryptionDecryptionUtill.decrypt(userMetadata.getDisplayName(), "user_pii", "", ""),
                    encryptionDecryptionUtill.decrypt(userMetadata.getProfilePictureUrl(), "user_pii", "", ""));
            responseWrapper.setResponse(userDetails);
            return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
        } catch (OAuth2AuthenticationException exception) {
            log.error("Error occurred while retrieving user profile : ", exception);
            return Utilities.handleErrorResponse(exception, USER_METADATA_FETCH_EXCEPTION.getCode(), exception.getStatus(), null);
        } catch (Exception exception) {
            log.error("Error occurred while retrieving user profile : ", exception);
            return Utilities.handleErrorResponse(exception, USER_METADATA_FETCH_EXCEPTION.getCode(), HttpStatus.INTERNAL_SERVER_ERROR, null);
        }

    }

    private UserMetadata fetchUserMetadata(String providerSubjectId) throws OAuth2AuthenticationException {
        try {
            return userMetadataRepository.findByProviderSubjectId(providerSubjectId)
                    .orElseThrow(() -> new OAuth2AuthenticationException("NOT_FOUND", "User not found. Please check your credentials or register.", HttpStatus.NOT_FOUND));
        } catch (DataAccessResourceFailureException exception) {
            throw new OAuth2AuthenticationException(DATABASE_CONNECTION_EXCEPTION.getCode(), DATABASE_CONNECTION_EXCEPTION.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        } catch (Exception exception) {
            throw new OAuth2AuthenticationException(USER_METADATA_FETCH_EXCEPTION.getCode(), USER_METADATA_FETCH_EXCEPTION.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private void validateIdentityProvider(UserMetadata userMetadata, String identityProvider) throws OAuth2AuthenticationException {
        if (!userMetadata.getIdentityProvider().equals(identityProvider)) {
            throw new OAuth2AuthenticationException("UNAUTHORIZED", "Identity provider mismatch", HttpStatus.UNAUTHORIZED);
        }
    }
}
