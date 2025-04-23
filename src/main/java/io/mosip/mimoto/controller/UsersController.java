package io.mosip.mimoto.controller;

import io.mosip.mimoto.constant.SwaggerExampleConstants;
import io.mosip.mimoto.constant.SwaggerLiteralConstants;
import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dbentity.UserMetadata;
import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.mimoto.UserMetadataDTO;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.OAuth2AuthenticationException;
import io.mosip.mimoto.repository.UserMetadataRepository;
import io.mosip.mimoto.util.EncryptionDecryptionUtil;
import io.mosip.mimoto.util.Utilities;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static io.mosip.mimoto.exception.ErrorConstants.SESSION_EXPIRED_OR_INVALID;
import static io.mosip.mimoto.util.Utilities.getErrorResponseEntityFromPlatformErrorMessage;

@Slf4j
@RestController
@RequestMapping(value = "/users/me")
@Tag(name = SwaggerLiteralConstants.USERS_NAME, description = SwaggerLiteralConstants.USERS_DESCRIPTION)
public class UsersController {
    @Autowired
    private UserMetadataRepository userMetadataRepository;

    @Autowired
    private EncryptionDecryptionUtil encryptionDecryptionUtill;

    @Operation(summary = "Retrieve user metadata from the database", description = "This API is secured using session-based authentication. When a request is made, the server retrieves the session ID from the Cookie header and uses it to fetch session details from Redis. From the session, it extracts the user's unique identifier (typically the sub field provided by the identity provider) along with the clientRegistrationId. These values are then used to retrieve the user's metadata from the database. If successful, the API returns the user's profile information. If any issue occurs such as missing user data or server error then an appropriate error response is returned.", operationId = "getUserProfileFromDB", security = @SecurityRequirement(name = "SessionAuth"))
    @ApiResponse(responseCode = "200", description = "User profile retrieved successfully from the Database", content = @Content(mediaType = "application/json", schema = @Schema(implementation = UserMetadataDTO.class), examples = @ExampleObject(name = "Success response", value = SwaggerExampleConstants.FETCH_USER_PROFILE_SUCCESS)))
    @ApiResponse(responseCode = "404", description = "User not found", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(name = "User not found in the Database", value = "{\"errorCode\": \"RESIDENT-APP-049\", \"errorMessage\": \"User not found. Please check your credentials or login again\"}")))
    @ApiResponse(responseCode = "500", description = "Internal server error", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = {@ExampleObject(name = "Database connection failure", value = "{\"errorCode\": \"RESIDENT-APP-047\", \"errorMessage\": \"Failed to connect to the shared database while fetching User Metadata data from the database\"}"), @ExampleObject(name = "Unexpected server error", value = "{\"errorCode\": \"RESIDENT-APP-049\", \"errorMessage\": \"An unexpected error occurred while retrieving user profile from the database\"}"), @ExampleObject(name = "User metadata not found in the Database", value = "{\"errorCode\": \"RESIDENT-APP-049\", \"errorMessage\": \"An unexpected error occurred while downloading and storing user metadata into database\"}")}))
    @GetMapping("/db")
    public ResponseEntity<UserMetadataDTO> getUserProfile(Authentication authentication, HttpSession session) {

        String identityProvider = (String) session.getAttribute("clientRegistrationId");
        UserMetadata userMetadata = null;
        try {
            userMetadata = fetchUserMetadata(authentication.getName(), identityProvider);
        } catch (OAuth2AuthenticationException exception) {
            log.error("Error occurred while retrieving user profile : ", exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, ErrorConstants.INVALID_USER.getErrorCode(), exception.getStatus(), null);
        }

        UserMetadataDTO userMetadataDTO = new UserMetadataDTO(encryptionDecryptionUtill.decrypt(userMetadata.getDisplayName(),
                EncryptionDecryptionUtil.USER_PII_KEY_REFERENCE_ID, "", ""),
                encryptionDecryptionUtill.decrypt(userMetadata.getProfilePictureUrl(),
                        EncryptionDecryptionUtil.USER_PII_KEY_REFERENCE_ID, "", ""),
                encryptionDecryptionUtill.decrypt(userMetadata.getEmail(), EncryptionDecryptionUtil.USER_PII_KEY_REFERENCE_ID,
                        "", ""));

        return ResponseEntity.status(HttpStatus.OK).body(userMetadataDTO);

    }

    private UserMetadata fetchUserMetadata(String providerSubjectId, String identityProvider) throws OAuth2AuthenticationException {
        return userMetadataRepository.findByProviderSubjectIdAndIdentityProvider(providerSubjectId, identityProvider).orElseThrow(() -> new OAuth2AuthenticationException(ErrorConstants.INVALID_USER.getErrorCode(), "User not found. Please check your credentials or login again", HttpStatus.NOT_FOUND));
    }

    @Operation(summary = "Retrieve user metadata from the stored redis session", description = "This API is secured using session-based authentication. When a request is made, the server retrieves the session ID from the Cookie header and uses it to fetch session details from Redis. It then attempts to retrieve the user's metadata directly from the session. If the metadata is available, the API returns the user's profile information otherwise an appropriate error response is returned.", operationId = "getUserProfileFromCache", security = @SecurityRequirement(name = "SessionAuth"))
    @ApiResponse(responseCode = "200", description = "User profile retrieved successfully from the session", content = @Content(mediaType = "application/json", schema = @Schema(implementation = UserMetadataDTO.class), examples = @ExampleObject(name = "Success response", value = SwaggerExampleConstants.FETCH_USER_PROFILE_SUCCESS)))
    @ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(name = "User metadata not found in session", value = "{\"errorCode\": \"RESIDENT-APP-052\", \"errorMessage\": \"No user metadata present in cache\"}")))
    @ApiResponse(responseCode = "500", description = "Internal server error", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(name = "Unexpected server error", value = "{\"errorCode\": \"RESIDENT-APP-052\", \"errorMessage\": \"An unexpected error occurred while retrieving user metadata from cache\"}")))
    @GetMapping("/cache")
    public ResponseEntity<UserMetadataDTO> getUserProfileFromCache(HttpSession session) {

        UserMetadataDTO userMetadataDTO = (UserMetadataDTO) session.getAttribute(SessionKeys.USER_METADATA);
        if (userMetadataDTO == null) {
            log.error("User info is not present in the session");
            return  getErrorResponseEntityFromPlatformErrorMessage(SESSION_EXPIRED_OR_INVALID, HttpStatus.UNAUTHORIZED, MediaType.APPLICATION_JSON);
        }
        return ResponseEntity.status(HttpStatus.OK).body(userMetadataDTO);

    }

}
