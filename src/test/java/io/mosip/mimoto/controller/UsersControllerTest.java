package io.mosip.mimoto.controller;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dbentity.UserMetadata;
import io.mosip.mimoto.dto.mimoto.UserMetadataDTO;
import io.mosip.mimoto.exception.DecryptionException;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.repository.UserMetadataRepository;
import io.mosip.mimoto.service.EncryptionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.util.Optional;

import static org.mockito.Mockito.when;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = UsersController.class)
@AutoConfigureMockMvc(addFilters = false)
@EnableWebMvc
class UsersControllerTest {
    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UserMetadataRepository userMetadataRepository;

    @MockBean
    private EncryptionService encryptionService;

    @Autowired
    private WebApplicationContext context;

    private MockHttpSession mockHttpSession;

    private static final String PROVIDER_SUBJECT_ID = "test-user";
    private static final String IDENTITY_PROVIDER = "test-provider";
    private static final String ENCRYPTED_DISPLAY_NAME = "encrypted-name";
    private static final String ENCRYPTED_PROFILE_PIC = "encrypted-pic";
    private static final String ENCRYPTED_EMAIL = "encrypted-email";
    private static final String DECRYPTED_DISPLAY_NAME = "Test User";
    private static final String DECRYPTED_PROFILE_PIC = "https://test.com/pic.jpg";
    private static final String DECRYPTED_EMAIL = "test@example.com";
    private static final String WALLET_ID = "test-wallet-id";

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context)
                .apply(springSecurity())
                .build();

        MockitoAnnotations.openMocks(this);
        mockHttpSession = new MockHttpSession();

    }

    @Test
    void getUserProfileOnlyFromCacheSuccessWithMockMvc() throws Exception {
        UserMetadataDTO userMetadataDTO = new UserMetadataDTO(DECRYPTED_DISPLAY_NAME, DECRYPTED_PROFILE_PIC, DECRYPTED_EMAIL, WALLET_ID);
        mockHttpSession.setAttribute(SessionKeys.USER_METADATA, userMetadataDTO);

        mockMvc.perform(get("/users/me")
                        .with(SecurityMockMvcRequestPostProcessors.user(DECRYPTED_DISPLAY_NAME).roles("USER"))
                        .session(mockHttpSession))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.displayName").value(DECRYPTED_DISPLAY_NAME))
                .andExpect(jsonPath("$.profilePictureUrl").value(DECRYPTED_PROFILE_PIC))
                .andExpect(jsonPath("$.email").value(DECRYPTED_EMAIL))
                .andExpect(jsonPath("$.walletId").value("test-wallet-id"));
    }

    @Test
    void getUserProfileOnlyFromDatabaseSuccessWithMockMvc() throws Exception {
        UserMetadata userMetadata = new UserMetadata();
        userMetadata.setDisplayName(ENCRYPTED_DISPLAY_NAME);
        userMetadata.setProfilePictureUrl(ENCRYPTED_PROFILE_PIC);
        userMetadata.setEmail(ENCRYPTED_EMAIL);
        mockHttpSession.setAttribute(SessionKeys.USER_METADATA, null);
        mockHttpSession.setAttribute("clientRegistrationId", IDENTITY_PROVIDER);
        when(userMetadataRepository.findByProviderSubjectIdAndIdentityProvider(PROVIDER_SUBJECT_ID, IDENTITY_PROVIDER))
                .thenReturn(Optional.of(userMetadata));
        when(encryptionService.decrypt(ENCRYPTED_DISPLAY_NAME)).thenReturn(DECRYPTED_DISPLAY_NAME);
        when(encryptionService.decrypt(ENCRYPTED_PROFILE_PIC)).thenReturn(DECRYPTED_PROFILE_PIC);
        when(encryptionService.decrypt(ENCRYPTED_EMAIL)).thenReturn(DECRYPTED_EMAIL);

        mockMvc.perform(get("/users/me")
                        .with(SecurityMockMvcRequestPostProcessors.user(PROVIDER_SUBJECT_ID).roles("USER"))
                        .session(mockHttpSession))
                .andExpect(status().isOk())
                .andExpect(result -> result.getResponse().getContentAsString())
                .andExpect(jsonPath("$.displayName").value(DECRYPTED_DISPLAY_NAME))
                .andExpect(jsonPath("$.profilePictureUrl").value(DECRYPTED_PROFILE_PIC))
                .andExpect(jsonPath("$.email").value(DECRYPTED_EMAIL));
    }

    @Test
    void getUserProfileOnlyUserNotFoundWithMockMvc() throws Exception {
        mockHttpSession.setAttribute(SessionKeys.USER_METADATA, null);
        mockHttpSession.setAttribute("clientRegistrationId", IDENTITY_PROVIDER);
        when(userMetadataRepository.findByProviderSubjectIdAndIdentityProvider(PROVIDER_SUBJECT_ID, IDENTITY_PROVIDER))
                .thenReturn(Optional.empty());

        mockMvc.perform(get("/users/me")
                        .with(SecurityMockMvcRequestPostProcessors.user(DECRYPTED_DISPLAY_NAME).roles("USER"))
                        .session(mockHttpSession))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.errorCode").value(ErrorConstants.INVALID_USER.getErrorCode()))
                .andExpect(jsonPath("$.errorMessage").value("User not found. Please check your credentials or login again"));
    }

    @Test
    void getUserProfileOnlyDecryptionExceptionWithMockMvc() throws Exception {
        UserMetadata userMetadata = new UserMetadata();
        userMetadata.setDisplayName(ENCRYPTED_DISPLAY_NAME);
        userMetadata.setProfilePictureUrl(ENCRYPTED_PROFILE_PIC);
        userMetadata.setEmail(ENCRYPTED_EMAIL);
        mockHttpSession.setAttribute(SessionKeys.USER_METADATA, null);
        mockHttpSession.setAttribute("clientRegistrationId", IDENTITY_PROVIDER);
        when(userMetadataRepository.findByProviderSubjectIdAndIdentityProvider(PROVIDER_SUBJECT_ID, IDENTITY_PROVIDER))
                .thenReturn(Optional.of(userMetadata));
        when(encryptionService.decrypt(ENCRYPTED_DISPLAY_NAME)).thenThrow(new DecryptionException("DECRYPTION_ERROR", "Decryption failed"));

        mockMvc.perform(get("/users/me")
                        .with(SecurityMockMvcRequestPostProcessors.user(PROVIDER_SUBJECT_ID).roles("USER"))
                        .session(mockHttpSession))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value(ErrorConstants.INTERNAL_SERVER_ERROR.getErrorCode()))
                .andExpect(jsonPath("$.errorMessage").value("Failed to process user data"));
    }

    @Test
    void getUserProfileOnlyMissingIdentityProviderWithMockMvc() throws Exception {
        mockHttpSession.setAttribute(SessionKeys.USER_METADATA, null);
        mockHttpSession.setAttribute("clientRegistrationId", null);

        mockMvc.perform(get("/users/me")
                        .with(SecurityMockMvcRequestPostProcessors.user(DECRYPTED_DISPLAY_NAME).roles("USER"))
                        .session(mockHttpSession))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.errorCode").value(ErrorConstants.INVALID_USER.getErrorCode()));
    }
}