package io.mosip.mimoto.controller;

import io.mosip.mimoto.constant.DPoPConstants;
import io.mosip.mimoto.dto.dpop.DPoPSession;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.service.DPoPSessionService;
import io.mosip.mimoto.service.IdpService;
import io.mosip.mimoto.service.impl.CredentialServiceImpl;
import io.mosip.mimoto.util.GlobalExceptionHandler;
import io.mosip.mimoto.util.TestUtilities;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.io.ByteArrayInputStream;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = {CredentialsController.class, GlobalExceptionHandler.class})
@AutoConfigureMockMvc(addFilters = false)
@EnableWebMvc
public class CredentialsControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private CredentialServiceImpl credentialService;

    @MockBean
    private IdpService idpService;

    @MockBean
    private DPoPSessionService dPoPSessionService;
    private String locale = "test-local", issuer = "test-issuer", credential = "test-credential", requestContent;
    private TokenResponseDTO tokenResponseDTO;

    @Before
    public void setUp() throws Exception {
        tokenResponseDTO = TestUtilities.getTokenResponseDTO();
        requestContent = EntityUtils.toString(new UrlEncodedFormEntity(List.of(
                new BasicNameValuePair("code", "test-code"),
                new BasicNameValuePair("issuer", issuer),
                new BasicNameValuePair("vcStorageExpiryLimitInTimes", "3"),
                new BasicNameValuePair("credential", credential),
                new BasicNameValuePair("locale", locale)
        )));
        stubDPoPSession();
    }

    private void stubDPoPSession() throws Exception {

        DPoPSession dPoPSession = DPoPSession.builder()
                .state("oauth-state")
                .alg("RS256")
                .build();

        org.mockito.Mockito.when(dPoPSessionService.find(any(), eq("oauth-state"))).thenReturn(dPoPSession);

        org.mockito.Mockito.when(dPoPSessionService.authorizationCodeParams(any(), eq("oauth-state"), any(), any()))
                .thenReturn(Map.of(
                        "code", "test-code",
                        "code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                        "redirect_uri", "https://example.com/cb",
                        "grant_type", "authorization_code",
                        "issuer", issuer,
                        "state", "oauth-state"));

        org.mockito.Mockito.when(idpService.exchangeAndBindToken(anyMap(), any())).thenReturn(tokenResponseDTO);

        org.mockito.Mockito.when(dPoPSessionService.credentialProof(any(), eq("oauth-state"), any(), any())).thenReturn("server-dPoP");

    }



    @Test
    public void should_downloadPdf_when_dPoPSessionIsValid() throws Exception {
        org.mockito.Mockito.when(credentialService.downloadCredentialAsPDF(issuer, credential, tokenResponseDTO, "3", locale, "server-dPoP"))

                .thenReturn(new ByteArrayInputStream("test-data".getBytes()));

        mockMvc.perform(post("/credentials/download")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .header("state", "oauth-state")
                        .content(requestContent))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_PDF));
        verify(idpService).exchangeAndBindToken(anyMap(), any());
        verify(idpService, never()).getTokenResponse(anyMap());
        verify(dPoPSessionService).remove(any(), eq("oauth-state"));
    }

    @Test
    public void should_rejectDownload_when_clientSendsAccessTokenWithoutDPoPSession() throws Exception {

        org.mockito.Mockito.reset(dPoPSessionService, idpService);

        String preIssuedContent = EntityUtils.toString(new UrlEncodedFormEntity(List.of(
                new BasicNameValuePair("issuer", issuer),
                new BasicNameValuePair("credential", credential),
                new BasicNameValuePair("locale", locale),
                new BasicNameValuePair("vcStorageExpiryLimitInTimes", "3"),
                new BasicNameValuePair("access_token", "pre-issued-token"),
                new BasicNameValuePair("token_type", "DPoP")
        )));

       mockMvc.perform(post("/credentials/download")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .header(DPoPConstants.DPOP_HEADER, "guest-dpop-proof")

                        .content(preIssuedContent))

                .andExpect(status().isBadRequest())

                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is("DPoP state is required")));



        verify(idpService, never()).getTokenResponse(anyMap());

        verify(idpService, never()).exchangeAndBindToken(anyMap(), any());

        verify(credentialService, never()).downloadCredentialAsPDF(any(), any(), any(), any(), any(), any());

    }



    @Test

    public void should_exchangeTokenInternally_when_dPoPSessionAndGrantAreProvided() throws Exception {

        org.mockito.Mockito.when(credentialService.downloadCredentialAsPDF(

                        eq(issuer), eq(credential), eq(tokenResponseDTO), eq("3"), eq(locale), eq("server-dPoP")))

                .thenReturn(new ByteArrayInputStream("test-data".getBytes()));



        mockMvc.perform(post("/credentials/download")

                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)

                        .header("state", "oauth-state")
                        .content(requestContent))

                .andExpect(status().isOk())

                .andExpect(content().contentType(MediaType.APPLICATION_PDF));



        verify(idpService).exchangeAndBindToken(anyMap(), any());

        verify(idpService, never()).getTokenResponse(anyMap());

        verify(dPoPSessionService).remove(any(), eq("oauth-state"));

    }



    @Test

    public void should_retryInternally_when_credentialIssuerRequiresNonce() throws Exception {

        HttpHeaders challengeHeaders = new HttpHeaders();

        challengeHeaders.set(DPoPConstants.DPOP_NONCE_HEADER, "issuer-nonce-123");

        challengeHeaders.set(DPoPConstants.WWW_AUTHENTICATE_HEADER, "DPoP error=\"use_dpop_nonce\"");

        org.mockito.Mockito.when(credentialService.downloadCredentialAsPDF(

                        eq(issuer), eq(credential), eq(tokenResponseDTO), eq("3"), eq(locale), eq("server-dPoP")))

                .thenThrow(new DPoPChallengeException(

                        HttpStatus.UNAUTHORIZED,

                        challengeHeaders,

                        "{\"error\":\"use_dpop_nonce\",\"error_description\":\"DPoP nonce required\"}"));

        org.mockito.Mockito.when(dPoPSessionService.retryCredentialProof(any(), eq("oauth-state"), any(), any(), any()))

                .thenReturn("retried-dPoP");

        org.mockito.Mockito.when(credentialService.downloadCredentialAsPDF(

                        eq(issuer), eq(credential), eq(tokenResponseDTO), eq("3"), eq(locale), eq("retried-dPoP")))

                .thenReturn(new ByteArrayInputStream("test-data".getBytes()));



        mockMvc.perform(post("/credentials/download")

                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)

                        .header("state", "oauth-state")
                        .content(requestContent))

                .andExpect(status().isOk())

                .andExpect(content().contentType(MediaType.APPLICATION_PDF));



        verify(dPoPSessionService).retryCredentialProof(any(), eq("oauth-state"), any(), any(), any());

        verify(dPoPSessionService).remove(any(), eq("oauth-state"));

    }



    @Test

    public void throwExceptionOnFetchingTokenResponseFailure() throws Exception {

        org.mockito.Mockito.when(idpService.exchangeAndBindToken(anyMap(), any()))

                .thenThrow(new IdpException("Exception occurred while performing the authorization"));



        mockMvc.perform(post("/credentials/download")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("state", "oauth-state")
                        .content(requestContent))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is("RESIDENT-APP-034")))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is("Exception occurred while performing the authorization")));

    }

    @Test
    public void throwExceptionOnFetchingIssuerOrAuthServerWellknownFailureDuringTokenGeneration() throws Exception {

        org.mockito.Mockito.when(idpService.exchangeAndBindToken(anyMap(), any()))

                .thenThrow(new ApiNotAccessibleException());

        mockMvc.perform(post("/credentials/download")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("state", "oauth-state")
                        .content(requestContent))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is("RESIDENT-APP-026")))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is("Api not accessible failure")));
    }


    @Test
    public void throwExceptionWhenPDFGenerationFailed() throws Exception {
    org.mockito.Mockito.when(credentialService.downloadCredentialAsPDF(issuer, credential, tokenResponseDTO, "3", locale, "server-dPoP"))

                .thenThrow(new ApiNotAccessibleException());

        mockMvc.perform(post("/credentials/download")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("state", "oauth-state")
                        .content(requestContent))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is("RESIDENT-APP-026")))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is("Api not accessible failure")));
    }

    @Test
    public void throwExceptionOnInvalidCredentialResource() throws Exception {
        org.mockito.Mockito.when(credentialService.downloadCredentialAsPDF(issuer, credential, tokenResponseDTO, "3", locale, "server-dPoP"))

                .thenThrow(new InvalidCredentialResourceException(
                        ErrorConstants.REQUEST_TIMED_OUT.getErrorCode(),
                        ErrorConstants.REQUEST_TIMED_OUT.getErrorMessage()));

        mockMvc.perform(post("/credentials/download")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("state", "oauth-state")
                        .content(requestContent))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is("request_timed_out")))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is("We are unable to process your request right now")));
    }

    @Test
    public void throwExceptionOnVCVerificationFailure() throws Exception {
        org.mockito.Mockito.when(credentialService.downloadCredentialAsPDF(issuer, credential, tokenResponseDTO, "3", locale, "server-dPoP"))

                .thenThrow(new VCVerificationException("Verification Failed!", "Error occurred when verifying the downloaded credential"));

        mockMvc.perform(post("/credentials/download")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .accept(MediaType.APPLICATION_JSON)
                        .header("state", "oauth-state")
                        .content(requestContent))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is("Verification Failed!")))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is("Error occurred when verifying the downloaded credential")));
    }
}
