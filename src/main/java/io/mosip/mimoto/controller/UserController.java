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
            String identityProvider = (String) session.getAttribute("clientRegistrationId");

            UserMetadata userMetadata = fetchUserMetadata(authentication.getName(), identityProvider);

            String userDetails = String.format("{\"displayName\": \"%s\", \"profilePictureUrl\": \"%s\", \"email\": \"%s\"}",
                    encryptionDecryptionUtill.decrypt(userMetadata.getDisplayName(), "user_pii", "", ""),
                    encryptionDecryptionUtill.decrypt(userMetadata.getProfilePictureUrl(), "user_pii", "", ""),
                    encryptionDecryptionUtill.decrypt(userMetadata.getEmail(), "user_pii", "", ""));
            responseWrapper.setResponse(userDetails);
            return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
        } catch (OAuth2AuthenticationException exception) {
            log.error("Error occurred while retrieving user profile : ", exception);
            return Utilities.handleErrorResponse(exception, USER_METADATA_FETCH_EXCEPTION.getCode(), exception.getStatus(), null);
        } catch (DataAccessResourceFailureException exception) {
            log.error("Error occurred while connecting to the database : ", exception);
            OAuth2AuthenticationException authenticationException = new OAuth2AuthenticationException(DATABASE_CONNECTION_EXCEPTION.getCode(), DATABASE_CONNECTION_EXCEPTION.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
            return Utilities.handleErrorResponse(authenticationException, USER_METADATA_FETCH_EXCEPTION.getCode(), authenticationException.getStatus(), null);
        } catch (Exception exception) {
            log.error("Error occurred while retrieving user profile : ", exception);
            OAuth2AuthenticationException authenticationException = new OAuth2AuthenticationException(USER_METADATA_FETCH_EXCEPTION.getCode(), USER_METADATA_FETCH_EXCEPTION.getMessage() + " due to : " + exception.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
            return Utilities.handleErrorResponse(authenticationException, USER_METADATA_FETCH_EXCEPTION.getCode(), authenticationException.getStatus(), null);
        }

    }

    private UserMetadata fetchUserMetadata(String providerSubjectId, String identityProvider) throws OAuth2AuthenticationException {
        return userMetadataRepository.findByProviderSubjectIdAndIdentityProvider(providerSubjectId, identityProvider)
                .orElseThrow(() -> new OAuth2AuthenticationException(USER_METADATA_FETCH_EXCEPTION.getCode(), "User not found. Please check your credentials or register", HttpStatus.NOT_FOUND));
    }
}
