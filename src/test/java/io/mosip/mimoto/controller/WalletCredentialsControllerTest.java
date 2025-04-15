package io.mosip.mimoto.controller;

import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.VerifiableCredentialResponseDTO;
import io.mosip.mimoto.dto.resident.WalletCredentialResponseDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.IdpException;
import io.mosip.mimoto.service.impl.WalletCredentialServiceImpl;
import io.mosip.mimoto.util.CredentialUtilService;
import jakarta.servlet.http.HttpSession;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.core.io.InputStreamResource;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.*;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = WalletCredentialsController.class)
@AutoConfigureMockMvc(addFilters = false)
@EnableWebMvc
public class WalletCredentialsControllerTest {

    @InjectMocks
    private WalletCredentialsController controller;

    @MockBean
    private WalletCredentialServiceImpl walletCredentialService;

    @MockBean
    private CredentialUtilService credentialUtilService;

    @MockBean
    private HttpSession httpSession;

    @Autowired
    private MockMvc mockMvc;

    VerifiableCredentialResponseDTO verifiableCredentialResponseDTO;
    String postRequestContent, getRequestContent, mockWalletKey = "mock-wallet-key", walletId = "wallet123", locale = "test-local", credential = "test-credential", issuer = "test-issuer", credentialId = "cred123", fileName = "credential.pdf";
    byte[] fileBytes = "Sample PDF".getBytes();
    WalletCredentialResponseDTO responseDTO;

    @Before
    public void setup() throws IOException {
        MockitoAnnotations.openMocks(this);
        verifiableCredentialResponseDTO = VerifiableCredentialResponseDTO.builder()
                .issuerName("issuerName123")
                .issuerLogo("issuerLogo")
                .credentialType("credentialType123")
                .credentialTypeLogo("credentialTypeLogo")
                .credentialId("credentialId123")
                .build();
        postRequestContent = EntityUtils.toString(new UrlEncodedFormEntity(List.of(
                new BasicNameValuePair("grant_type", "authorization_code"),
                new BasicNameValuePair("code", "test-code"),
                new BasicNameValuePair("redirect_uri", "test-redirect_uri"),
                new BasicNameValuePair("code_verifier", "test-code_verifier"),
                new BasicNameValuePair("issuer", issuer),
                new BasicNameValuePair("vcStorageExpiryLimitInTimes", "3"),
                new BasicNameValuePair("credential", credential),
                new BasicNameValuePair("locale", locale)
        )));
        getRequestContent = EntityUtils.toString(new UrlEncodedFormEntity(List.of(
                new BasicNameValuePair("locale", locale)
        )));
        responseDTO = new WalletCredentialResponseDTO(new InputStreamResource(new ByteArrayInputStream(fileBytes)), fileName);
    }

    @Test
    public void shouldDownloadCredentialForValidWalletAndDetails() throws Exception {
        when(credentialUtilService.getTokenResponse(anyMap(), eq(issuer))).thenReturn(new TokenResponseDTO());
        when(walletCredentialService.fetchAndStoreCredential(anyString(), anyString(), any(), anyString(), anyString(), anyString(), anyString()))
                .thenReturn(verifiableCredentialResponseDTO);

        mockMvc.perform(post(String.format("/wallets/%s/credentials", walletId))
                        .accept(MediaType.APPLICATION_JSON)
                        .sessionAttr("wallet_key", "mockWalletKey")
                        .sessionAttr("wallet_id", walletId)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content(postRequestContent))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer_name").value("issuerName123"))
                .andExpect(jsonPath("$.issuer_logo").value("issuerLogo"))
                .andExpect(jsonPath("$.credential_type").value("credentialType123"))
                .andExpect(jsonPath("$.credential_type_logo").value("credentialTypeLogo"))
                .andExpect(jsonPath("$.credential_id").value("credentialId123"));
    }

    @Test
    public void shouldThrowExceptionIfWalletIdIsMissingWhileDownloadingCredential() throws Exception {
        mockMvc.perform(get(String.format("/wallets/%s/credentials", walletId))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content(getRequestContent))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("RESIDENT-APP-054"))
                .andExpect(jsonPath("$.errorMessage").value("Wallet Id is missing in session"));
    }

    @Test
    public void shouldThrowExceptionIfReceivedWalletIdAndSessionWalletIdMismatchWhileDownloadCredential() throws Exception {
        mockMvc.perform(get(String.format("/wallets/%s/credentials", walletId))
                        .sessionAttr("wallet_id", "wallet124")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content(getRequestContent))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("RESIDENT-APP-054"))
                .andExpect(jsonPath("$.errorMessage").value("Invalid Wallet Id. Session and request Wallet Id do not match"));
    }

    @Test
    public void shouldThrowExceptionIfWalletKeyIsMissingWhileDownloadingCredential() throws Exception {
        mockMvc.perform(post(String.format("/wallets/%s/credentials", walletId))
                        .sessionAttr("wallet_id", walletId)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content(postRequestContent))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("RESIDENT-APP-053"))
                .andExpect(jsonPath("$.errorMessage").value("Wallet Key is missing in session"));
    }


    @Test
    public void shouldThrowExceptionOnFetchingTokenResponseFailure() throws Exception {
        when(credentialUtilService.getTokenResponse(anyMap(), eq(issuer)))
                .thenThrow(new IdpException("Exception occurred while performing the authorization"));

        mockMvc.perform(post(String.format("/wallets/%s/credentials", walletId))
                        .sessionAttr("wallet_key", mockWalletKey)
                        .sessionAttr("wallet_id", walletId)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content(postRequestContent))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("RESIDENT-APP-034"))
                .andExpect(jsonPath("$.errorMessage").value("Exception occurred while performing the authorization"));
    }

    @Test
    public void shouldThrowExceptionOnFetchingIssuerOrAuthServerWellknownFailureDuringTokenGeneration() throws Exception {
        Mockito.when(credentialUtilService.getTokenResponse(Mockito.anyMap(), eq(issuer)))
                .thenThrow(new ApiNotAccessibleException());

        mockMvc.perform(post(String.format("/wallets/%s/credentials", walletId))
                        .sessionAttr("wallet_key", mockWalletKey)
                        .sessionAttr("wallet_id", walletId)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content(postRequestContent))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode", Matchers.is("RESIDENT-APP-026")))
                .andExpect(jsonPath("$.errorMessage", Matchers.is("Api not accessible failure")));
    }

    @Test
    public void shouldThrowExceptionOnDatabaseConnectionFailureDuringCredentialDownload() throws Exception {
        when(credentialUtilService.getTokenResponse(anyMap(), eq(issuer))).thenReturn(new TokenResponseDTO());
        when(walletCredentialService.fetchAndStoreCredential(anyString(), anyString(), any(), anyString(), anyString(), anyString(), anyString()))
                .thenThrow(new DataAccessResourceFailureException("Exception occurred when connecting to the database to store the credential response"));

        mockMvc.perform(post(String.format("/wallets/%s/credentials", walletId))
                        .sessionAttr("wallet_key", mockWalletKey)
                        .sessionAttr("wallet_id", walletId)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content(postRequestContent))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("RESIDENT-APP-047"))
                .andExpect(jsonPath("$.errorMessage").value("Failed to connect to the shared database while Storing Verifiable Credential data into the database"));
    }

    @Test
    public void shouldThrowExceptionOnAnyErrorOccurredDuringCredentialDownload() throws Exception {
        when(httpSession.getAttribute("wallet_key")).thenReturn(mockWalletKey);
        when(credentialUtilService.getTokenResponse(anyMap(), anyString())).thenThrow(new RuntimeException("Unexpected error occurred while downloading credential"));

        mockMvc.perform(post(String.format("/wallets/%s/credentials", walletId))
                        .sessionAttr("wallet_key", mockWalletKey)
                        .sessionAttr("wallet_id", walletId)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content(postRequestContent))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("RESIDENT-APP-053"))
                .andExpect(jsonPath("$.errorMessage").value("Unexpected error occurred while downloading credential"));
    }

    @Test
    public void shouldFetchAllCredentialsForValidWalletAndDetails() throws Exception {
        List<VerifiableCredentialResponseDTO> mockList = Collections.singletonList(verifiableCredentialResponseDTO);

        when(walletCredentialService.fetchAllCredentialsForWallet(walletId, mockWalletKey, locale)).thenReturn(mockList);

        mockMvc.perform(get(String.format("/wallets/%s/credentials", walletId))
                        .sessionAttr("wallet_key", mockWalletKey)
                        .sessionAttr("wallet_id", walletId)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content(getRequestContent))
                .andExpect(status().isOk());
    }

    @Test
    public void shouldThrowExceptionIfWalletIdIsMissingWhileFetchingAllCredentials() throws Exception {
        mockMvc.perform(get(String.format("/wallets/%s/credentials", walletId))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content(getRequestContent))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("RESIDENT-APP-054"))
                .andExpect(jsonPath("$.errorMessage").value("Wallet Id is missing in session"));
    }

    @Test
    public void shouldThrowExceptionIfReceivedWalletIdAndSessionWalletIdMismatchWhileFetchingAllCredentials() throws Exception {
        mockMvc.perform(get(String.format("/wallets/%s/credentials", walletId))
                        .sessionAttr("wallet_id", "wallet124")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content(getRequestContent))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("RESIDENT-APP-054"))
                .andExpect(jsonPath("$.errorMessage").value("Invalid Wallet Id. Session and request Wallet Id do not match"));
    }

    @Test
    public void shouldThrowExceptionIfWalletKeyIsMissingWhileFetchingAllCredentials() throws Exception {
        mockMvc.perform(get(String.format("/wallets/%s/credentials", walletId))
                        .sessionAttr("wallet_id", walletId)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content(getRequestContent))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("RESIDENT-APP-054"))
                .andExpect(jsonPath("$.errorMessage").value("Wallet Key is missing in session"));
    }

    @Test
    public void shouldThrowExceptionOnDatabaseConnectionFailureWhileFetchingCredentials() throws Exception {
        when(walletCredentialService.fetchAllCredentialsForWallet(walletId, mockWalletKey, locale))
                .thenThrow(new DataAccessResourceFailureException("Exception occurred when connecting to the database to store the credential response"));

        mockMvc.perform(get(String.format("/wallets/%s/credentials", walletId))
                        .sessionAttr("wallet_key", mockWalletKey)
                        .sessionAttr("wallet_id", walletId)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content(getRequestContent))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("RESIDENT-APP-047"))
                .andExpect(jsonPath("$.errorMessage").value("Failed to connect to the shared database while Fetching Verifiable Credential data into the database"));
    }

    @Test
    public void shouldThrowExceptionOnAnyErrorOccurredWhileFetchingCredentials() throws Exception {
        when(httpSession.getAttribute("wallet_key")).thenReturn(mockWalletKey);
        when(walletCredentialService.fetchAllCredentialsForWallet(anyString(), anyString(), anyString()))
                .thenThrow(new RuntimeException("Unexpected error occurred while fetching wallet credentials"));

        mockMvc.perform(get(String.format("/wallets/%s/credentials", walletId))
                        .sessionAttr("wallet_key", "mockWalletKey")
                        .sessionAttr("wallet_id", walletId)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content(getRequestContent))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("RESIDENT-APP-054"))
                .andExpect(jsonPath("$.errorMessage").value("Unexpected error occurred while fetching wallet credentials"));
    }


    @Test
    public void shouldReturnPDFByteStreamWithInlineContentDispositionInHeaderForValidRequestWithActionAsPreview() throws Exception {
        Mockito.when(walletCredentialService.fetchVerifiableCredential(walletId, credentialId, mockWalletKey, "en"))
                .thenReturn(responseDTO);

        mockMvc.perform(get(String.format("/wallets/%s/credentials/%s", walletId, credentialId))
                        .param("locale", "en")
                        .param("action", "preview")
                        .sessionAttr("wallet_key", mockWalletKey)
                        .sessionAttr("wallet_id", walletId))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CONTENT_DISPOSITION, "inline; filename=\"credential.pdf\""))
                .andExpect(content().contentType(MediaType.APPLICATION_PDF));
    }

    @Test
    public void shouldReturnPDFByteStreamWithAttachmentContentDispositionInHeaderForValidRequestWithActionAsDownload() throws Exception {
        Mockito.when(walletCredentialService.fetchVerifiableCredential(walletId, credentialId, mockWalletKey, "en"))
                .thenReturn(responseDTO);

        mockMvc.perform(get(String.format("/wallets/%s/credentials/%s", walletId, credentialId))
                        .param("locale", "en")
                        .param("action", "download")
                        .sessionAttr("wallet_key", mockWalletKey)
                        .sessionAttr("wallet_id", walletId))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"credential.pdf\""))
                .andExpect(content().contentType(MediaType.APPLICATION_PDF));
    }

    @Test
    public void shouldThrowExceptionIfWalletIdIsMissingWhileFetchingCredential() throws Exception {
        mockMvc.perform(get(String.format("/wallets/%s/credentials/%s", walletId, credentialId))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content(getRequestContent))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("RESIDENT-APP-055"))
                .andExpect(jsonPath("$.errorMessage").value("Wallet Id is missing in session"));
    }

    @Test
    public void shouldThrowExceptionIfReceivedWalletIdAndSessionWalletIdMismatchWhileFetchingCredential() throws Exception {
        mockMvc.perform(get(String.format("/wallets/%s/credentials/%s", walletId, credentialId))
                        .sessionAttr("wallet_id", "wallet124")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content(getRequestContent))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("RESIDENT-APP-055"))
                .andExpect(jsonPath("$.errorMessage").value("Invalid Wallet Id. Session and request Wallet Id do not match"));
    }

    @Test
    public void shouldThrowExceptionIfWalletKeyIsMissingWhileFetchingAllCredential() throws Exception {
        mockMvc.perform(get(String.format("/wallets/%s/credentials/%s", walletId, credentialId))
                        .sessionAttr("wallet_id", walletId)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content(getRequestContent))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.errorCode").value("RESIDENT-APP-055"))
                .andExpect(jsonPath("$.errorMessage").value("Wallet Key is missing in session"));
    }

    @Test
    public void shouldThrowExceptionOnDatabaseConnectionFailureWhileFetchingCredential() throws Exception {
        Mockito.when(walletCredentialService.fetchVerifiableCredential(eq(walletId), eq(credentialId), anyString(), eq("en")))
                .thenThrow(new DataAccessResourceFailureException("Exception occurred when connecting to the database to fetch the Verifiable credential"));

        mockMvc.perform(get(String.format("/wallets/%s/credentials/%s", walletId, credentialId))
                        .param("locale", "en")
                        .param("action", "download")
                        .sessionAttr("wallet_key", mockWalletKey)
                        .sessionAttr("wallet_id", walletId))
                .andExpect(status().isInternalServerError())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.errorCode").value("RESIDENT-APP-047"))
                .andExpect(jsonPath("$.errorMessage").value("Failed to connect to the shared database while Fetching Verifiable Credential data into the database"));
    }

    @Test
    public void shouldThrowExceptionOnAnyErrorOccurredWhileFetchingCredential() throws Exception {
        Mockito.when(walletCredentialService.fetchVerifiableCredential(eq(walletId), eq(credentialId), anyString(), eq("en")))
                .thenThrow(new RuntimeException("Unexpected error occurred while fetching wallet credentials"));

        mockMvc.perform(get(String.format("/wallets/%s/credentials/%s", walletId, credentialId))
                        .param("locale", "en")
                        .param("action", "download")
                        .sessionAttr("wallet_key", mockWalletKey)
                        .sessionAttr("wallet_id", walletId))
                .andExpect(status().isInternalServerError())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.errorCode").value("RESIDENT-APP-055"))
                .andExpect(jsonPath("$.errorMessage").value("Unexpected error occurred while fetching wallet credentials"));
    }
}
