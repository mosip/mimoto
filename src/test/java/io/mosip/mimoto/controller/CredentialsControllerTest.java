package io.mosip.mimoto.controller;

import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.service.impl.CredentialServiceImpl;
import io.mosip.mimoto.util.CredentialUtilService;
import io.mosip.mimoto.util.TestUtilities;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.io.ByteArrayInputStream;
import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = CredentialsController.class)
@AutoConfigureMockMvc(addFilters = false)
@EnableWebMvc
public class CredentialsControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private CredentialServiceImpl credentialService;

    @MockBean
    private CredentialUtilService credentialUtilService;

    private String locale = "test-local", issuer = "test-issuer", credential = "test-credential", requestContent;
    private TokenResponseDTO tokenResponseDTO;

    @Before
    public void setUp() throws Exception {
        tokenResponseDTO = TestUtilities.getTokenResponseDTO();
        Mockito.when(credentialUtilService.getTokenResponse(Mockito.anyMap(), Mockito.eq(issuer))).thenReturn(tokenResponseDTO);
        requestContent = EntityUtils.toString(new UrlEncodedFormEntity(List.of(
                new BasicNameValuePair("grant_type", "authorization_code"),
                new BasicNameValuePair("code", "test-code"),
                new BasicNameValuePair("redirect_uri", "test-redirect_uri"),
                new BasicNameValuePair("code_verifier", "test-code_verifier"),
                new BasicNameValuePair("issuer", issuer),
                new BasicNameValuePair("vcStorageExpiryLimitInTimes", "3"),
                new BasicNameValuePair("credential", credential),
                new BasicNameValuePair("locale", locale)
        )));
    }

    @Test
    public void downloadPDFSuccessfully() throws Exception {
        Mockito.when(credentialService.downloadCredentialAsPDF(issuer, credential, tokenResponseDTO, "3", locale))
                .thenReturn(new ByteArrayInputStream("test-data".getBytes()));

        mockMvc.perform(post("/credentials/download")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content(requestContent))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_PDF));
    }

    @Test
    public void throwExceptionOnFetchingTokenResponseFailure() throws Exception {
        Mockito.when(credentialUtilService.getTokenResponse(Mockito.anyMap(), Mockito.eq(issuer)))
                .thenThrow(new IdpException("Exception occurred while performing the authorization"));

        mockMvc.perform(post("/credentials/download")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content(requestContent))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is("RESIDENT-APP-034")))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is("Exception occurred while performing the authorization")));

    }

    @Test
    public void throwExceptionOnFetchingIssuerOrAuthServerWellknownFailureDuringTokenGeneration() throws Exception {
        Mockito.when(credentialUtilService.getTokenResponse(Mockito.anyMap(), Mockito.eq(issuer)))
                .thenThrow(new ApiNotAccessibleException());

        mockMvc.perform(post("/credentials/download")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content(requestContent))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is("RESIDENT-APP-026")))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is("Api not accessible failure")));
    }


    @Test
    public void throwExceptionWhenPDFGenerationFailed() throws Exception {
        Mockito.when(credentialService.downloadCredentialAsPDF(issuer, credential, tokenResponseDTO, "3", locale))
                .thenThrow(new ApiNotAccessibleException());

        mockMvc.perform(post("/credentials/download")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content(requestContent))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is("RESIDENT-APP-026")))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is("Api not accessible failure")));
    }

    @Test
    public void throwExceptionOnInvalidCredentialResource() throws Exception {
        Mockito.when(credentialService.downloadCredentialAsPDF(issuer, credential, tokenResponseDTO, "3", locale))
                .thenThrow(new InvalidCredentialResourceException(
                        ErrorConstants.REQUEST_TIMED_OUT.getErrorCode(),
                        ErrorConstants.REQUEST_TIMED_OUT.getErrorMessage()));

        mockMvc.perform(post("/credentials/download")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content(requestContent))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is("request_timed_out")))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is("We are unable to process your request right now")));
    }

    @Test
    public void throwExceptionOnVCVerificationFailure() throws Exception {
        Mockito.when(credentialService.downloadCredentialAsPDF(issuer, credential, tokenResponseDTO, "3", locale))
                .thenThrow(new VCVerificationException("Verification Failed!", "Error occurred when verifying the downloaded credential"));

        mockMvc.perform(post("/credentials/download")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content(requestContent))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is("Verification Failed!")))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is("Error occurred when verifying the downloaded credential")));
    }
}
