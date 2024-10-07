package io.mosip.mimoto.controller;

import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.service.impl.CredentialServiceImpl;
import io.mosip.mimoto.util.TestUtilities;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
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
import java.util.Arrays;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = CredentialsController.class)
@AutoConfigureMockMvc(addFilters = false)
@EnableWebMvc
public class CredentialsControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private CredentialServiceImpl credentialService;

    @Test
    public void downloadPDFSuccessfully() throws Exception {

        String issuer = "test-issuer";
        String credential = "test-credential";
        TokenResponseDTO tokenResponseDTO = TestUtilities.getTokenResponseDTO();
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream("test-data".getBytes());
        Mockito.when(credentialService.getTokenResponse(Mockito.anyMap(), Mockito.eq(issuer))).thenReturn(tokenResponseDTO);
        Mockito.when(credentialService.downloadCredentialAsPDF(Mockito.eq(issuer), Mockito.eq(credential), Mockito.eq(tokenResponseDTO), Mockito.eq("3"))).thenReturn(byteArrayInputStream);

        mockMvc.perform(post("/credentials/download")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content(EntityUtils.toString(new UrlEncodedFormEntity(Arrays.asList(
                                new BasicNameValuePair("grant_type", "authorization_code"),
                                new BasicNameValuePair("code", "test-code"),
                                new BasicNameValuePair("redirect_uri", "test-redirect_uri"),
                                new BasicNameValuePair("code_verifier", "test-code_verifier"),
                                new BasicNameValuePair("issuer", issuer),
                                new BasicNameValuePair("vcExpiryTimes", "3"),
                                new BasicNameValuePair("credential", credential)
                        )))))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_PDF))
                .andReturn()
                .getResponse()
                .getContentAsString();
    }


    @Test
    public void throwExceptionWhenTokenIsNotFetched() throws Exception {

        String issuer = "test-issuer";
        String credential = "test-credential";
        Mockito.when(credentialService.getTokenResponse(Mockito.anyMap(), Mockito.eq(issuer))).thenThrow(ApiNotAccessibleException.class);

        mockMvc.perform(post("/credentials/download")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content(EntityUtils.toString(new UrlEncodedFormEntity(Arrays.asList(
                                new BasicNameValuePair("grant_type", "authorization_code"),
                                new BasicNameValuePair("code", "test-code"),
                                new BasicNameValuePair("redirect_uri", "test-redirect_uri"),
                                new BasicNameValuePair("code_verifier", "test-code_verifier"),
                                new BasicNameValuePair("issuer", issuer),
                                new BasicNameValuePair("vcExpiryTimes", "3"),
                                new BasicNameValuePair("credential", credential)
                        )))))
                .andExpect(status().isBadRequest())
                .andReturn()
                .getResponse()
                .getContentAsString();
    }

    @Test
    public void throwExceptionWhenPDFGenerationFailed() throws Exception {

        String issuer = "test-issuer";
        String credential = "test-credential";
        TokenResponseDTO tokenResponseDTO = TestUtilities.getTokenResponseDTO();
        Mockito.when(credentialService.getTokenResponse(Mockito.anyMap(), Mockito.eq(issuer))).thenReturn(tokenResponseDTO);
        Mockito.when(credentialService.downloadCredentialAsPDF(Mockito.eq(issuer), Mockito.eq(credential), Mockito.eq(tokenResponseDTO), Mockito.eq("3") )).thenThrow(ApiNotAccessibleException.class);

        mockMvc.perform(post("/credentials/download")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content(EntityUtils.toString(new UrlEncodedFormEntity(Arrays.asList(
                                new BasicNameValuePair("grant_type", "authorization_code"),
                                new BasicNameValuePair("code", "test-code"),
                                new BasicNameValuePair("redirect_uri", "test-redirect_uri"),
                                new BasicNameValuePair("code_verifier", "test-code_verifier"),
                                new BasicNameValuePair("issuer", issuer),
                                new BasicNameValuePair("vcExpiryTimes", "3"),
                                new BasicNameValuePair("credential", credential)
                        )))))
                .andExpect(status().isBadRequest())
                .andReturn()
                .getResponse()
                .getContentAsString();
    }

}
