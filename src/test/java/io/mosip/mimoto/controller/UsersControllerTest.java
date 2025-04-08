package io.mosip.mimoto.controller;

import io.mosip.mimoto.dbentity.UserMetadata;
import io.mosip.mimoto.dto.mimoto.UserMetadataDTO;
import io.mosip.mimoto.repository.UserMetadataRepository;
import io.mosip.mimoto.util.EncryptionDecryptionUtil;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.util.Optional;

import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = UsersController.class)
@AutoConfigureMockMvc
@EnableWebMvc
@EnableWebSecurity
public class UsersControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UserMetadataRepository userMetadataRepository;

    @MockBean
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    @Autowired
    private WebApplicationContext context;

    private UserMetadata userMetadata;

    MockHttpSession mockSession;

    String identityProvider, userId;

    @Before
    public void setUp() {
        identityProvider = "google";
        userMetadata = new UserMetadata();
        userMetadata.setIdentityProvider(identityProvider);
        userMetadata.setDisplayName("encryptedName");
        userMetadata.setProfilePictureUrl("encryptedUrl");
        userMetadata.setEmail("encryptedEmail");
        mockMvc = MockMvcBuilders.webAppContextSetup(context)
                .apply(springSecurity())
                .build();
        mockSession = new MockHttpSession();
        mockSession.setAttribute("clientRegistrationId", "google");
        mockSession.setAttribute("userId", "user123");
        userId = (String) mockSession.getAttribute("userId");
        when(userMetadataRepository.findByProviderSubjectIdAndIdentityProvider("user123", identityProvider)).thenReturn(Optional.of(userMetadata));
        when(encryptionDecryptionUtil.decrypt("encryptedName", "user_pii", "", "")).thenReturn("Name 123");
        when(encryptionDecryptionUtil.decrypt("encryptedUrl", "user_pii", "", "")).thenReturn("https://profile.com/pic.jpg");
        when(encryptionDecryptionUtil.decrypt("encryptedEmail", "user_pii", "", "")).thenReturn("name123@gmail.com");

    }

    @Test
    public void shouldReturnTheUserDataForValidValues() throws Exception {
        mockMvc.perform(get("/users/me/db").accept(MediaType.APPLICATION_JSON)
                        .with(SecurityMockMvcRequestPostProcessors.user("user123").roles("USER")).session(mockSession))
                .andExpect(status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.display_name").value("Name 123"))
                .andExpect(MockMvcResultMatchers.jsonPath("$.profile_picture_url").value("https://profile.com/pic.jpg"))
                .andExpect(MockMvcResultMatchers.jsonPath("$.email").value("name123@gmail.com"))
                .andExpect(jsonPath("$.errorCode").doesNotExist())
                .andExpect(jsonPath("$.errorMessage").doesNotExist());
    }

    @Test
    public void shouldThrowExceptionForAInvalidUser() throws Exception {
        when(userMetadataRepository.findByProviderSubjectIdAndIdentityProvider("user123", identityProvider)).thenReturn(Optional.empty());

        mockMvc.perform(get("/users/me/db").accept(MediaType.APPLICATION_JSON)
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user("user123").roles("USER")).session(mockSession))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.errorCode").value("RESIDENT-APP-049"))
                .andExpect(jsonPath("$.errorMessage").value("User not found. Please check your credentials or login again"));
    }

    @Test
    public void shouldThrowExceptionIfAnyOtherErrorOccurredWhileFetchingUserData() throws Exception {
        when(userMetadataRepository.findByProviderSubjectIdAndIdentityProvider("user123", identityProvider)).thenReturn(Optional.of(userMetadata));
        when(encryptionDecryptionUtil.decrypt("encryptedName", "user_pii", "", "")).thenThrow(new RuntimeException("Failure occurred while decrypting the name"));

        mockMvc.perform(get("/users/me/db").accept(MediaType.APPLICATION_JSON)
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user("user123").roles("USER")).session(mockSession))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("RESIDENT-APP-049"))
                .andExpect(jsonPath("$.errorMessage").value("Failed to fetch the User metadata from database due to : Failure occurred while decrypting the name"));
    }

    @Test
    public void shouldReturnUserProfileFromCacheForValidSession() throws Exception {
        UserMetadataDTO userMetadataDTO = new UserMetadataDTO("Name 123", "https://profile.com/pic.jpg", "name123@gmail.com");
        mockSession.setAttribute("userMetadata", userMetadataDTO);

        mockMvc.perform(get("/users/me/cache")
                        .accept(MediaType.APPLICATION_JSON)
                        .with(SecurityMockMvcRequestPostProcessors.user("user123").roles("USER"))
                        .session(mockSession))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.display_name").value("Name 123"))
                .andExpect(jsonPath("$.profile_picture_url").value("https://profile.com/pic.jpg"))
                .andExpect(jsonPath("$.email").value("name123@gmail.com"));
    }

    @Test
    public void shouldReturnInternalServerErrorForCacheError() throws Exception {
        mockSession.setAttribute("userMetadata", null);

        mockMvc.perform(get("/users/me/cache")
                        .accept(MediaType.APPLICATION_JSON)
                        .with(SecurityMockMvcRequestPostProcessors.user("user123").roles("USER"))
                        .session(mockSession))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("RESIDENT-APP-052"))
                .andExpect(jsonPath("$.errorMessage").value("No user metadata present in cache"));
    }

}