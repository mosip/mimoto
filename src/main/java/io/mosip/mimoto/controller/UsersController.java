package io.mosip.mimoto.controller;

import io.mosip.mimoto.dbentity.UserMetadata;
import io.mosip.mimoto.dto.mimoto.UserMetadataDTO;
import io.mosip.mimoto.exception.LoginSessionException;
import io.mosip.mimoto.exception.DatabaseConnectionException;
import io.mosip.mimoto.exception.OAuth2AuthenticationException;
import io.mosip.mimoto.model.DatabaseEntity;
import io.mosip.mimoto.model.DatabaseOperation;
import io.mosip.mimoto.repository.UserMetadataRepository;
import io.mosip.mimoto.util.EncryptionDecryptionUtil;
import io.mosip.mimoto.util.Utilities;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import static io.mosip.mimoto.exception.PlatformErrorMessages.*;

@Slf4j
@RestController
@RequestMapping(value = "/users/me")
public class UsersController {

    @Autowired
    private UserMetadataRepository userMetadataRepository;

    @Autowired
    private EncryptionDecryptionUtil encryptionDecryptionUtill;

    @GetMapping("/db")
    public ResponseEntity<UserMetadataDTO> getUserProfile(Authentication authentication, HttpSession session) {
        try {
            String identityProvider = (String) session.getAttribute("clientRegistrationId");

            UserMetadata userMetadata = fetchUserMetadata(authentication.getName(), identityProvider);

            UserMetadataDTO userMetadataDTO = new UserMetadataDTO(encryptionDecryptionUtill.decrypt(userMetadata.getDisplayName(), "user_pii", "", ""),
                    encryptionDecryptionUtill.decrypt(userMetadata.getProfilePictureUrl(), "user_pii", "", ""),
                    encryptionDecryptionUtill.decrypt(userMetadata.getEmail(), "user_pii", "", ""));

            return ResponseEntity.status(HttpStatus.OK).body(userMetadataDTO);
        } catch (OAuth2AuthenticationException exception) {
            log.error("Error occurred while retrieving user profile : ", exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, USER_METADATA_FETCH_EXCEPTION.getCode(), exception.getStatus(), null);
        } catch (DataAccessResourceFailureException exception) {
            log.error("Error occurred while connecting to the database : ", exception);
            DatabaseConnectionException connectionException = new DatabaseConnectionException(DATABASE_CONNECTION_EXCEPTION.getCode(), DATABASE_CONNECTION_EXCEPTION.getMessage(), DatabaseEntity.USERMETADATA, DatabaseOperation.FETCHING, HttpStatus.INTERNAL_SERVER_ERROR);
            return Utilities.getErrorResponseEntityWithoutWrapper(connectionException, USER_METADATA_FETCH_EXCEPTION.getCode(), connectionException.getStatus(), null);
        } catch (Exception exception) {
            log.error("Error occurred while retrieving user profile : ", exception);
            OAuth2AuthenticationException authenticationException = new OAuth2AuthenticationException(USER_METADATA_FETCH_EXCEPTION.getCode(), USER_METADATA_FETCH_EXCEPTION.getMessage() + " due to : " + exception.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
            return Utilities.getErrorResponseEntityWithoutWrapper(authenticationException, USER_METADATA_FETCH_EXCEPTION.getCode(), authenticationException.getStatus(), null);
        }
    }

    private UserMetadata fetchUserMetadata(String providerSubjectId, String identityProvider) throws OAuth2AuthenticationException {
        return userMetadataRepository.findByProviderSubjectIdAndIdentityProvider(providerSubjectId, identityProvider)
                .orElseThrow(() -> new OAuth2AuthenticationException(USER_METADATA_FETCH_EXCEPTION.getCode(), "User not found. Please check your credentials or login again", HttpStatus.NOT_FOUND));
    }

    @GetMapping("/cache")
    public ResponseEntity<UserMetadataDTO> getUserProfileFromCache(Authentication authentication, HttpSession session) {
        try {
            UserMetadataDTO userMetadataDTO = (UserMetadataDTO) session.getAttribute("userMetadata");
            if (userMetadataDTO == null) {
                throw new LoginSessionException(USER_METADATA_CACHE_FETCH_EXCEPTION.getCode(), "No user metadata present in cache", HttpStatus.INTERNAL_SERVER_ERROR);
            }
            return ResponseEntity.status(HttpStatus.OK).body(userMetadataDTO);
        }  catch (Exception exception) {
            log.error("Error occurred while retrieving user profile from cache : ", exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, USER_METADATA_CACHE_FETCH_EXCEPTION.getCode(), HttpStatus.INTERNAL_SERVER_ERROR, null);
        }

    }

}
