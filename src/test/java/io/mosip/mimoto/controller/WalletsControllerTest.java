package io.mosip.mimoto.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.CreateWalletRequestDto;
import io.mosip.mimoto.dto.WalletResponseDto;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.util.GlobalExceptionHandler;
import io.mosip.mimoto.service.WalletService;
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
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = {WalletsController.class, GlobalExceptionHandler.class})
@AutoConfigureMockMvc
@EnableWebMvc
@EnableWebSecurity
public class WalletsControllerTest {
    @MockBean
    private WalletValidator walletValidator;

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private WalletService walletService;

    CreateWalletRequestDto createWalletRequestDto;

    MockHttpSession mockSession;

    String userId, walletName, walletPin, confirmWalletPin, walletId;

    @Before
    public void setUp() {
        walletName = "My Wallet";
        walletPin = "1234";
        confirmWalletPin = "1234";
        walletId = "walletId123";
        createWalletRequestDto = new CreateWalletRequestDto();
        createWalletRequestDto.setWalletName(walletName);
        createWalletRequestDto.setWalletPin(walletPin);
        createWalletRequestDto.setConfirmWalletPin(confirmWalletPin);
        mockSession = new MockHttpSession();
        mockSession.setAttribute("clientRegistrationId", "google");
        mockSession.setAttribute(SessionKeys.USER_ID, "user123");
        userId = (String) mockSession.getAttribute(SessionKeys.USER_ID);
    }

    @Test
    public void shouldReturnWalletIdForSuccessfulWalletCreation() throws Exception {
        when(walletService.createWallet(userId, walletName, walletPin, confirmWalletPin)).thenReturn(walletId);

        mockMvc.perform(post("/wallets")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(createWalletRequestDto))
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user(userId).roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isOk())
                .andExpect(content().string(walletId));
    }

    @Test
    public void shouldThrowExceptionIfAnyErrorOccurredWhenCreatingWallet() throws Exception {
        when(walletService.createWallet(userId, walletName, walletPin, confirmWalletPin))
                .thenThrow(new RuntimeException("Exception occurred when creating Wallet for given userId"));

        mockMvc.perform(post("/wallets")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(createWalletRequestDto))
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user(userId).roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("internal_server_error"))
                .andExpect(jsonPath("$.errorMessage").value("We are unable to process request now"));
    }

    @Test
    public void shouldThrowExceptionIfReceivedPINAndConfirmPINDoNotMatch() throws Exception {
        createWalletRequestDto.setConfirmWalletPin("2345");
        when(walletService.createWallet(userId, walletName, walletPin, "2345"))
                .thenThrow(new InvalidRequestException(ErrorConstants.INVALID_REQUEST.getErrorCode(), "Entered PIN and Confirm PIN do not match"));

        mockMvc.perform(post("/wallets")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(createWalletRequestDto))
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user(userId).roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("invalid_request"))
                .andExpect(jsonPath("$.errorMessage").value("invalid_request --> Entered PIN and Confirm PIN do not match"));
    }

    @Test
    public void shouldReturnListOfWalletIDsForValidUserId() throws Exception {
        List<WalletResponseDto> wallets = List.of(new WalletResponseDto("wallet1"),
                new WalletResponseDto("wallet2"));
        when(walletService.getWallets(userId)).thenReturn(wallets);

        mockMvc.perform(get("/wallets")
                        .accept(MediaType.APPLICATION_JSON)
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user(userId).roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isOk())
                .andExpect(content().string("[{\"walletId\":\"wallet1\"},{\"walletId\":\"wallet2\"}]"));
    }

    @Test
    public void shouldThrowExceptionIfAnyErrorOccurredWhileFetchingWalletsForGivenUserId() throws Exception {
        when(walletService.getWallets(userId)).thenThrow(new RuntimeException("Exception occurred when fetching the wallets for given userId"));

        mockMvc.perform(get("/wallets")
                        .session(mockSession)
                        .accept(MediaType.APPLICATION_JSON)
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user(userId).roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("internal_server_error"))
                .andExpect(jsonPath("$.errorMessage").value("We are unable to process request now"));
    }

    @Test
    public void shouldReturnTheWalletIDAndStoreWalletKeyInSessionForValidUserAndWalletId() throws Exception {
        when(walletService.getWalletKey(userId, walletId, walletPin)).thenReturn(walletId);
        String expectedWalletKey = "walletId123";

        MvcResult result = mockMvc.perform(post(String.format("/wallets/%s/unlock", walletId))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(createWalletRequestDto))
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user(userId).roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isOk())
                .andExpect(content().string("{\"walletId\":\"walletId123\"}"))
                .andReturn();

        String actualWalletKey = result.getRequest().getSession().getAttribute("wallet_key").toString();
        assertEquals(expectedWalletKey, actualWalletKey);
    }

    @Test
    public void shouldThrowExceptionIfAnyErrorOccurredWhileFetchingWalletDataForGivenUserIdAndWalletId() throws Exception {
        when(walletService.getWalletKey(userId, walletId, walletPin)).thenThrow(new RuntimeException("Exception occurred when fetching the wallet data for given walletId and userId"));

        mockMvc.perform(post(String.format("/wallets/%s/unlock", walletId))
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(createWalletRequestDto))
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user(userId).roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("internal_server_error"))
                .andExpect(jsonPath("$.errorMessage").value("We are unable to process request now"));
    }

    @Test
    public void shouldDeleteWalletSuccessfully() throws Exception {
        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete(String.format("/wallets/%s", walletId))
                        .accept(MediaType.APPLICATION_JSON)
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user(userId).roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isOk());
    }

    @Test
    public void shouldClearSessionAttributesWhenDeletingCurrentWallet() throws Exception {
        mockSession.setAttribute(SessionKeys.WALLET_ID, walletId);
        mockSession.setAttribute(SessionKeys.WALLET_KEY, "walletKey123");

        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete(String.format("/wallets/%s", walletId))
                        .accept(MediaType.APPLICATION_JSON)
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user(userId).roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isOk());

        // Session attributes should be cleared
        assertEquals(null, mockSession.getAttribute(SessionKeys.WALLET_ID));
        assertEquals(null, mockSession.getAttribute(SessionKeys.WALLET_KEY));
    }

    @Test
    public void shouldReturnUnauthorizedWhenUserIdIsMissingForDeleteWallet() throws Exception {
        MockHttpSession sessionWithoutUserId = new MockHttpSession();

        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete(String.format("/wallets/%s", walletId))
                        .accept(MediaType.APPLICATION_JSON)
                        .session(sessionWithoutUserId)
                        .with(SecurityMockMvcRequestPostProcessors.user(userId).roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isUnauthorized());
    }
}
