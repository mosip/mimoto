package io.mosip.mimoto.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dbentity.UserMetadata;
import io.mosip.mimoto.dto.WalletRequestDto;
import io.mosip.mimoto.repository.UserMetadataRepository;
import io.mosip.mimoto.service.WalletService;
import io.mosip.mimoto.util.EncryptionDecryptionUtil;
import io.mosip.mimoto.util.WalletValidator;
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
import static org.junit.Assert.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.util.List;
import java.util.Optional;

import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = UserController.class)
@AutoConfigureMockMvc
@EnableWebMvc
@EnableWebSecurity
public class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UserMetadataRepository userMetadataRepository;

    @MockBean
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    @MockBean
    private WalletValidator walletValidator;

    @Autowired
    private WebApplicationContext context;

    @MockBean
    private WalletService walletService;

    private UserMetadata userMetadata;

    MockHttpSession mockSession;

    String identityProvider, userId;

    WalletRequestDto walletRequestDto;

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

        walletRequestDto = new WalletRequestDto();
        walletRequestDto.setName("My Wallet");
        walletRequestDto.setPin("1234");
    }

    @Test
    public void shouldReturnTheUserDataForValidValues() throws Exception {
        mockMvc.perform(get("/users/me").accept(MediaType.APPLICATION_JSON)
                        .with(SecurityMockMvcRequestPostProcessors.user("user123").roles("USER")).session(mockSession))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.display_name").value("Name 123"))
                .andExpect(MockMvcResultMatchers.jsonPath("$.profile_picture_url").value("https://profile.com/pic.jpg"))
                .andExpect(MockMvcResultMatchers.jsonPath("$.email").value("name123@gmail.com"))
                .andExpect(jsonPath("$.errorCode").doesNotExist())
                .andExpect(jsonPath("$.errorMessage").doesNotExist());
    }

    @Test
    public void shouldThrowExceptionForAInvalidUser() throws Exception {
        when(userMetadataRepository.findByProviderSubjectIdAndIdentityProvider("user123", identityProvider)).thenReturn(Optional.empty());

        mockMvc.perform(get("/users/me").accept(MediaType.APPLICATION_JSON)
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user("user123").roles("USER")).session(mockSession))
                .andExpect(MockMvcResultMatchers.status().isNotFound())
                .andExpect(jsonPath("$.errorCode").value("RESIDENT-APP-049"))
                .andExpect(jsonPath("$.errorMessage").value("User not found. Please check your credentials or register"));
    }

    @Test
    public void shouldThrowExceptionIfAnyOtherErrorOccurredWhileFetchingUserData() throws Exception {
        when(userMetadataRepository.findByProviderSubjectIdAndIdentityProvider("user123", identityProvider)).thenReturn(Optional.of(userMetadata));
        when(encryptionDecryptionUtil.decrypt("encryptedName", "user_pii", "", "")).thenThrow(new RuntimeException("Failure occurred while decrypting the name"));

        mockMvc.perform(get("/users/me").accept(MediaType.APPLICATION_JSON)
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user("user123").roles("USER")).session(mockSession))
                .andExpect(MockMvcResultMatchers.status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("RESIDENT-APP-049"))
                .andExpect(jsonPath("$.errorMessage").value("Failed to fetch the User metadata from database due to : Failure occurred while decrypting the name"));
    }

    @Test
    public void shouldReturnWalletIdForSuccessfulWalletCreation() throws Exception {
        when(walletService.createWallet(userId, "My Wallet", "1234")).thenReturn("walletId123");

        mockMvc.perform(post("/users/me/wallets")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(walletRequestDto))
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user("user123").roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isOk())
                .andExpect(content().string("walletId123"));
    }

    @Test
    public void shouldThrowExceptionIfAnyErrorOccurredWhenCreatingWallet() throws Exception {
        when(walletService.createWallet(userId, "My Wallet", "1234"))
                .thenThrow(new RuntimeException("Exception occurred when creating Wallet for given userId"));

        mockMvc.perform(post("/users/me/wallets")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(walletRequestDto))
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user("user123").roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("RESIDENT-APP-050"))
                .andExpect(jsonPath("$.errorMessage").value("Exception occurred when creating Wallet for given userId"));
    }


    @Test
    public void shouldReturnListOfWalletIDsForValidUserId() throws Exception {
        List<String> wallets = List.of("wallet1", "wallet2");
        when(walletService.getWallets(userId)).thenReturn(wallets);

        mockMvc.perform(get("/users/me/wallets")
                        .accept(MediaType.APPLICATION_JSON)
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user("user123").roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isOk())
                .andExpect(content().string("[\"wallet1\",\"wallet2\"]"));
    }

    @Test
    public void shouldThrowExceptionIfAnyErrorOccurredWhileFetchingWalletsForGivenUserId() throws Exception {
        when(walletService.getWallets(userId)).thenThrow(new RuntimeException("Exception occurred when fetching the wallets for given userId"));

        mockMvc.perform(get("/users/me/wallets")
                        .session(mockSession)
                        .accept(MediaType.APPLICATION_JSON)
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user("user123").roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("RESIDENT-APP-051"))
                .andExpect(jsonPath("$.errorMessage").value("Exception occurred when fetching the wallets for given userId"));
    }

    @Test
    public void shouldReturnTheWalletIDAndStoreWalletKeyInSessionForValidUserAndWalletId() throws Exception {
        when(walletService.getWalletKey(userId, "walletId123", "1234")).thenReturn("walletId123");
        String expectedWalletKey = "walletId123";

        MvcResult result = mockMvc.perform(post("/users/me/wallets/walletId123")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(walletRequestDto))
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user("user123").roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isOk())
                .andExpect(content().string("walletId123"))
                .andReturn();

        String actualWalletKey = result.getRequest().getSession().getAttribute("wallet_key").toString();
        assertEquals(expectedWalletKey, actualWalletKey);
    }

    @Test
    public void shouldThrowExceptionIfAnyErrorOccurredWhileFetchingWalletDataForGivenUserIdAndWalletId() throws Exception {
        when(walletService.getWalletKey(userId, "walletId123", "1234")).thenThrow(new RuntimeException("Exception occurred when fetching the wallet data for given walletId and userId"));

        mockMvc.perform(post("/users/me/wallets/walletId123")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(walletRequestDto))
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user("user123").roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("RESIDENT-APP-051"))
                .andExpect(jsonPath("$.errorMessage").value("Exception occurred when fetching the wallet data for given walletId and userId"));
    }
}