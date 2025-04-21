package io.mosip.mimoto.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.WalletRequestDto;
import io.mosip.mimoto.dto.WalletResponseDto;
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
@SpringBootTest(classes = WalletsController.class)
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

    WalletRequestDto walletRequestDto;

    MockHttpSession mockSession;

    String userId;

    @Before
    public void setUp() {
        walletRequestDto = new WalletRequestDto();
        walletRequestDto.setWalletName("My Wallet");
        walletRequestDto.setWalletPin("1234");
        mockSession = new MockHttpSession();
        mockSession.setAttribute("clientRegistrationId", "google");
        mockSession.setAttribute(SessionKeys.USER_ID, "user123");
        userId = (String) mockSession.getAttribute(SessionKeys.USER_ID);
    }

    @Test
    public void shouldReturnWalletIdForSuccessfulWalletCreation() throws Exception {
        when(walletService.createWallet(userId, "My Wallet", "1234")).thenReturn("walletId123");

        mockMvc.perform(post("/wallets")
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

        mockMvc.perform(post("/wallets")
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
        List<WalletResponseDto> wallets = List.of(new WalletResponseDto("wallet1"),
                new WalletResponseDto("wallet2"));
        when(walletService.getWallets(userId)).thenReturn(wallets);

        mockMvc.perform(get("/wallets")
                        .accept(MediaType.APPLICATION_JSON)
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user("user123").roles("USER"))
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

        MvcResult result = mockMvc.perform(post("/wallets/walletId123/unlock")
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(walletRequestDto))
                        .session(mockSession)
                        .with(SecurityMockMvcRequestPostProcessors.user("user123").roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isOk())
                .andExpect(content().string("{\"walletId\":\"walletId123\"}"))
                .andReturn();

        String actualWalletKey = result.getRequest().getSession().getAttribute("wallet_key").toString();
        assertEquals(expectedWalletKey, actualWalletKey);
    }

    @Test
    public void shouldThrowExceptionIfAnyErrorOccurredWhileFetchingWalletDataForGivenUserIdAndWalletId() throws Exception {
        when(walletService.getWalletKey(userId, "walletId123", "1234")).thenThrow(new RuntimeException("Exception occurred when fetching the wallet data for given walletId and userId"));

        mockMvc.perform(post("/wallets/walletId123/unlock")
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
