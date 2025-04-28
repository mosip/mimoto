package io.mosip.mimoto.controller;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dbentity.UserMetadata;
import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.mimoto.UserMetadataDTO;
import io.mosip.mimoto.exception.DecryptionException;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.repository.UserMetadataRepository;
import io.mosip.mimoto.service.EncryptionService;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;

import java.util.Optional;

import static io.mosip.mimoto.exception.ErrorConstants.SESSION_EXPIRED_OR_INVALID;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

class UsersControllerTest {

    @InjectMocks
    private UsersController usersController;

    @Mock
    private UserMetadataRepository userMetadataRepository;

    @Mock
    private EncryptionService encryptionService;

    @Mock
    private Authentication authentication;

    @Mock
    private HttpSession session;

    private static final String PROVIDER_SUBJECT_ID = "test-user";
    private static final String IDENTITY_PROVIDER = "test-provider";
    private static final String ENCRYPTED_DISPLAY_NAME = "encrypted-name";
    private static final String ENCRYPTED_PROFILE_PIC = "encrypted-pic";
    private static final String ENCRYPTED_EMAIL = "encrypted-email";
    private static final String DECRYPTED_DISPLAY_NAME = "Test User";
    private static final String DECRYPTED_PROFILE_PIC = "http://test.com/pic.jpg";
    private static final String DECRYPTED_EMAIL = "test@example.com";

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    // Tests for getUserProfile (Database)
    @Test
    void getUserProfileSuccess() throws Exception {
        // Arrange
        UserMetadata userMetadata = new UserMetadata();
        userMetadata.setDisplayName(ENCRYPTED_DISPLAY_NAME);
        userMetadata.setProfilePictureUrl(ENCRYPTED_PROFILE_PIC);
        userMetadata.setEmail(ENCRYPTED_EMAIL);

        when(authentication.getName()).thenReturn(PROVIDER_SUBJECT_ID);
        when(session.getAttribute("clientRegistrationId")).thenReturn(IDENTITY_PROVIDER);
        when(userMetadataRepository.findByProviderSubjectIdAndIdentityProvider(PROVIDER_SUBJECT_ID, IDENTITY_PROVIDER))
                .thenReturn(Optional.of(userMetadata));
        when(encryptionService.decrypt(ENCRYPTED_DISPLAY_NAME)).thenReturn(DECRYPTED_DISPLAY_NAME);
        when(encryptionService.decrypt(ENCRYPTED_PROFILE_PIC)).thenReturn(DECRYPTED_PROFILE_PIC);
        when(encryptionService.decrypt(ENCRYPTED_EMAIL)).thenReturn(DECRYPTED_EMAIL);

        // Act
        ResponseEntity<UserMetadataDTO> response = usersController.getUserProfile(authentication, session);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        UserMetadataDTO result = response.getBody();
        assertNotNull(result);
        assertEquals(DECRYPTED_DISPLAY_NAME, result.getDisplayName());
        assertEquals(DECRYPTED_PROFILE_PIC, result.getProfilePictureUrl());
        assertEquals(DECRYPTED_EMAIL, result.getEmail());
    }

    @Test
    void getUserProfileUserNotFound() {
        // Arrange
        when(authentication.getName()).thenReturn(PROVIDER_SUBJECT_ID);
        when(session.getAttribute("clientRegistrationId")).thenReturn(IDENTITY_PROVIDER);
        when(userMetadataRepository.findByProviderSubjectIdAndIdentityProvider(PROVIDER_SUBJECT_ID, IDENTITY_PROVIDER))
                .thenReturn(Optional.empty());

        // Act
        ResponseEntity<?> response = usersController.getUserProfile(authentication, session);

        // Assert
        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        ErrorDTO error = (ErrorDTO) response.getBody();
        assertNotNull(error);
        assertEquals(ErrorConstants.INVALID_USER.getErrorCode(), error.getErrorCode());
        assertEquals("User not found. Please check your credentials or login again", error.getErrorMessage());
    }

    @Test
    void getUserProfileDecryptionException() throws Exception {
        // Arrange
        UserMetadata userMetadata = new UserMetadata();
        userMetadata.setDisplayName(ENCRYPTED_DISPLAY_NAME);
        userMetadata.setProfilePictureUrl(ENCRYPTED_PROFILE_PIC);
        userMetadata.setEmail(ENCRYPTED_EMAIL);

        when(authentication.getName()).thenReturn(PROVIDER_SUBJECT_ID);
        when(session.getAttribute("clientRegistrationId")).thenReturn(IDENTITY_PROVIDER);
        when(userMetadataRepository.findByProviderSubjectIdAndIdentityProvider(PROVIDER_SUBJECT_ID, IDENTITY_PROVIDER))
                .thenReturn(Optional.of(userMetadata));
        when(encryptionService.decrypt(ENCRYPTED_DISPLAY_NAME)).thenThrow(new DecryptionException("DECRYPTION_ERROR", "Decryption failed"));

        // Act & Assert
        RuntimeException exception = assertThrows(RuntimeException.class,
                () -> usersController.getUserProfile(authentication, session));
        assertTrue(exception.getCause() instanceof DecryptionException);
    }

    // Tests for getUserProfileFromCache
    @Test
    void getUserProfileFromCacheSuccess() {
        // Arrange
        UserMetadataDTO userMetadataDTO = new UserMetadataDTO(DECRYPTED_DISPLAY_NAME, DECRYPTED_PROFILE_PIC, DECRYPTED_EMAIL);
        when(session.getAttribute(SessionKeys.USER_METADATA)).thenReturn(userMetadataDTO);

        // Act
        ResponseEntity<UserMetadataDTO> response = usersController.getUserProfileFromCache(session);

        // Assert
        assertEquals(HttpStatus.OK, response.getStatusCode());
        UserMetadataDTO result = response.getBody();
        assertNotNull(result);
        assertEquals(DECRYPTED_DISPLAY_NAME, result.getDisplayName());
        assertEquals(DECRYPTED_PROFILE_PIC, result.getProfilePictureUrl());
        assertEquals(DECRYPTED_EMAIL, result.getEmail());
    }

    @Test
    void getUserProfileFromCacheNoMetadataInSession() {
        // Arrange
        when(session.getAttribute(SessionKeys.USER_METADATA)).thenReturn(null);

        // Act
        ResponseEntity<?> response = usersController.getUserProfileFromCache(session);

        // Assert
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        ErrorDTO error = (ErrorDTO) response.getBody();
        assertNotNull(error);
        assertEquals(SESSION_EXPIRED_OR_INVALID.getErrorCode(), error.getErrorCode());
        assertEquals(SESSION_EXPIRED_OR_INVALID.getErrorMessage(), error.getErrorMessage());
    }

    @Test
    void getUserProfileFromCacheNullSession() {
        // Arrange
        when(session.getAttribute(SessionKeys.USER_METADATA)).thenReturn(null);

        // Act
        ResponseEntity<?> response = usersController.getUserProfileFromCache(session);

        // Assert
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        ErrorDTO error = (ErrorDTO) response.getBody();
        assertNotNull(error);
        assertEquals(SESSION_EXPIRED_OR_INVALID.getErrorCode(), error.getErrorCode());
    }
}