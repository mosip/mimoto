package io.mosip.mimoto.controller;

import io.mosip.mimoto.exception.OAuth2AuthenticationException;
import io.mosip.mimoto.service.TokenService;
import io.mosip.mimoto.service.TokenServiceFactory;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = {TokenAuthController.class})
@AutoConfigureMockMvc
public class TokenAuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private TokenServiceFactory tokenServiceFactory;

    @MockBean
    private TokenService tokenService;

    private String provider;
    private String idToken;
    private String authorizationHeader;

    @Before
    public void setUp() {
        provider = "google";
        idToken = "dummyIdToken";
        authorizationHeader = "Bearer " + idToken;
    }

    @Test
    public void shouldReturnSuccessForValidTokenAndProvider() throws Exception {
        when(tokenServiceFactory.isSupportedProvider(eq(provider))).thenReturn(true);
        when(tokenServiceFactory.getTokenService(eq(provider))).thenReturn(tokenService);
        doNothing().when(tokenService).processToken(eq(idToken), eq(provider), any(), any());

        mockMvc.perform(post("/auth/{provider}/token-login", provider)
                        .header("Authorization", authorizationHeader)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .with(SecurityMockMvcRequestPostProcessors.user("user123").roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$", is("Session created.")));

        verify(tokenServiceFactory).isSupportedProvider(eq(provider));
        verify(tokenServiceFactory).getTokenService(eq(provider));
        verify(tokenService).processToken(eq(idToken), eq(provider), any(), any());
    }

    @Test
    public void shouldReturnBadRequestForUnsupportedProvider() throws Exception {
        when(tokenServiceFactory.isSupportedProvider(eq(provider))).thenReturn(false);

        mockMvc.perform(post("/auth/{provider}/token-login", provider)
                        .header("Authorization", authorizationHeader)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .with(SecurityMockMvcRequestPostProcessors.user("user123").roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$", is(String.format("Unsupported provider: %s", provider))));

        verify(tokenServiceFactory).isSupportedProvider(eq(provider));
        verifyNoMoreInteractions(tokenServiceFactory);
        verifyNoInteractions(tokenService);
    }

    @Test
    public void shouldReturnUnauthorizedForMissingAuthorizationHeader() throws Exception {
        when(tokenServiceFactory.isSupportedProvider(eq(provider))).thenReturn(true);
        mockMvc.perform(post("/auth/google/token-login", provider)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .with(SecurityMockMvcRequestPostProcessors.user("user123").roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isBadRequest());

        verifyNoInteractions(tokenServiceFactory, tokenService);
    }

    @Test
    public void shouldReturnUnauthorizedForInvalidAuthorizationHeader() throws Exception {
        when(tokenServiceFactory.isSupportedProvider(eq(provider))).thenReturn(true);
        String invalidAuthorizationHeader = "InvalidToken";

        mockMvc.perform(post("/auth/google/token-login", provider)
                        .header("Authorization", invalidAuthorizationHeader)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .with(SecurityMockMvcRequestPostProcessors.user("user123").roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$", is("Bearer ID token required.")));
    }

    @Test
    public void shouldReturnUnauthorizedForInvalidToken() throws Exception {
        when(tokenServiceFactory.isSupportedProvider(eq(provider))).thenReturn(true);
        when(tokenServiceFactory.getTokenService(eq(provider))).thenReturn(tokenService);
        OAuth2AuthenticationException exception = new OAuth2AuthenticationException("invalid_token", "Invalid token format", HttpStatus.BAD_REQUEST);
        doThrow(exception).when(tokenService).processToken(eq(idToken), eq(provider), any(), any());

        mockMvc.perform(post("/auth/{provider}/token-login", provider)
                        .header("Authorization", authorizationHeader)
                        .contentType(MediaType.APPLICATION_JSON)
                        .accept(MediaType.APPLICATION_JSON)
                        .with(SecurityMockMvcRequestPostProcessors.user("user123").roles("USER"))
                        .with(SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$", is("Invalid or expired ID token: invalid_token --> Invalid token format")));

        verify(tokenServiceFactory).isSupportedProvider(eq(provider));
        verify(tokenServiceFactory).getTokenService(eq(provider));
        verify(tokenService).processToken(eq(idToken), eq(provider), any(), any());
    }
}