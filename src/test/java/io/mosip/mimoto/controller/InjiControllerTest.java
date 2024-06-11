package io.mosip.mimoto.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.google.common.collect.Lists;
import io.mosip.kernel.biometrics.spi.CbeffUtil;
import io.mosip.kernel.core.util.JsonUtils;
import io.mosip.kernel.websub.api.model.SubscriptionChangeResponse;
import io.mosip.mimoto.TestBootApplication;
import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.dto.DisplayDTO;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.dto.LogoDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.dto.resident.*;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.ApisResourceAccessException;
import io.mosip.mimoto.exception.BaseUncheckedException;
import io.mosip.mimoto.model.Event;
import io.mosip.mimoto.model.EventModel;
import io.mosip.mimoto.service.RestClientService;
import io.mosip.mimoto.service.impl.CredentialShareServiceImpl;
import io.mosip.mimoto.service.impl.IssuersServiceImpl;
import io.mosip.mimoto.util.*;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.*;
import java.util.stream.Collectors;

import static io.mosip.mimoto.exception.PlatformErrorMessages.API_NOT_ACCESSIBLE_EXCEPTION;
import static io.mosip.mimoto.exception.PlatformErrorMessages.INVALID_ISSUER_ID_EXCEPTION;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = TestBootApplication.class)
@AutoConfigureMockMvc
@PrepareForTest({Files.class})
public class InjiControllerTest {

    @Autowired
    private CommonInjiController commonInjiController = new CommonInjiController();

    @Autowired
    private CredentialShareController credentialShareController = new CredentialShareController();

    @MockBean
    private Map<String, String> injiConfig;

    @MockBean
    private CbeffUtil cbeffUtil;

    @MockBean
    private WebSubSubscriptionHelper webSubSubscriptionHelper;

    @MockBean
    private CredentialShareServiceImpl credentialShareService;

    @MockBean
    private IssuersServiceImpl issuersService;

    @MockBean
    public RestApiClient restApiClient;

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    Utilities utilities;

    @MockBean
    private AttestationOfflineVerify attestationOfflineVerify;

    @MockBean
    private AttestationOnlineVerify attestationOnlineVerify;

    @MockBean
    public RestClientService<Object> restClientService;

    @MockBean
    public CryptoCoreUtil cryptoCoreUtil;

    @Before
    public void setup() throws IOException {
        //PowerMockito.mockStatic(Files.class);
        //PowerMockito.doNothing().when(Files.write(Mockito.any(Path.class), Mockito.any(byte[].class)));

        Map<String, String> injiConfig = new HashMap<>();
        injiConfig.put("datashareUrl", "http://www.mosipdatashare.com");

        ReflectionTestUtils.setField(commonInjiController, "injiConfig", injiConfig);
        ReflectionTestUtils.setField(credentialShareController, "partnerEncryptionKey", "partnerkey");
        ReflectionTestUtils.setField(credentialShareController, "partnerId", "partnerId");
        ReflectionTestUtils.setField(credentialShareController, "topic", "topic");


        Mockito.when(utilities.getDataPath()).thenReturn("target");

        Mockito.when(webSubSubscriptionHelper.subscribeEvent(Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(new SubscriptionChangeResponse());
        Mockito.doNothing().when(webSubSubscriptionHelper).initSubscriptions();
        Mockito.doNothing().when(webSubSubscriptionHelper).registerTopic(Mockito.any());
        Mockito.doNothing().when(webSubSubscriptionHelper).publish(Mockito.any(), Mockito.any());
    }

    @Test
    public void getAllPropertiesTest() throws Exception {
        this.mockMvc.perform(get("/allProperties").accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isOk());
    }

    static IssuerDTO getIssuerDTO(String issuerName) {
        LogoDTO logo = new LogoDTO();
        logo.setUrl("/logo");
        logo.setAlt_text("logo-url");
        DisplayDTO display = new DisplayDTO();
        display.setName(issuerName);
        display.setTitle("Download via " + issuerName);
        display.setDescription(issuerName + " description");
        display.setLanguage("en");
        display.setLogo(logo);
        IssuerDTO issuer = new IssuerDTO();
        issuer.setCredential_issuer(issuerName + "id");
        issuer.setDisplay(Collections.singletonList(display));
        issuer.setClient_id("123");
        if (issuerName.equals("Issuer1")) issuer.setWellKnownEndpoint("/.well-known");
        else {
            issuer.setRedirect_uri(null);
            issuer.setAuthorization_endpoint(null);
            issuer.setCredential_endpoint(null);
            issuer.setToken_endpoint(null);
            issuer.setScopes_supported(null);
        }
        return issuer;
    }

    static CredentialsSupportedResponse getCredentialSupportedResponse(String credentialSupportedName){
        LogoDTO logo = new LogoDTO();
        logo.setUrl("/logo");
        logo.setAlt_text("logo-url");
        CredentialSupportedDisplayResponse credentialSupportedDisplay = new CredentialSupportedDisplayResponse();
        credentialSupportedDisplay.setLogo(logo);
        credentialSupportedDisplay.setName(credentialSupportedName);
        credentialSupportedDisplay.setLocale("en");
        credentialSupportedDisplay.setTextColor("#FFFFFF");
        credentialSupportedDisplay.setBackgroundColor("#B34622");
        CredentialIssuerDisplayResponse credentialIssuerDisplayResponse = new CredentialIssuerDisplayResponse();
        credentialIssuerDisplayResponse.setName("Given Name");
        credentialIssuerDisplayResponse.setLocale("en");
        CredentialDisplayResponseDto credentialDisplayResponseDto = new CredentialDisplayResponseDto();
        credentialDisplayResponseDto.setDisplay(Collections.singletonList(credentialIssuerDisplayResponse));
        CredentialDefinitionResponseDto credentialDefinitionResponseDto = new CredentialDefinitionResponseDto();
        credentialDefinitionResponseDto.setType(List.of("VerifiableCredential", credentialSupportedName));
        credentialDefinitionResponseDto.setCredentialSubject(Map.of("name", credentialDisplayResponseDto));
        CredentialsSupportedResponse credentialsSupportedResponse = new CredentialsSupportedResponse();
        credentialsSupportedResponse.setFormat("ldp_vc");
        credentialsSupportedResponse.setId(credentialSupportedName);
        credentialsSupportedResponse.setScope(credentialSupportedName+"_vc_ldp");
        credentialsSupportedResponse.setDisplay(Collections.singletonList(credentialSupportedDisplay));
        credentialsSupportedResponse.setProofTypesSupported(Collections.singletonList("jwt"));
        credentialsSupportedResponse.setCredentialDefinition(credentialDefinitionResponseDto);
        return credentialsSupportedResponse;
    }

    static CredentialIssuerWellKnownResponse getCredentialIssuerWellKnownResponseDto(String issuerName, List<CredentialsSupportedResponse> credentialsSupportedResponses){
        CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse = new CredentialIssuerWellKnownResponse();
        credentialIssuerWellKnownResponse.setCredentialIssuer(issuerName);
        credentialIssuerWellKnownResponse.setCredentialEndPoint("credential_endpoint");
        credentialIssuerWellKnownResponse.setCredentialsSupported(credentialsSupportedResponses);
        return credentialIssuerWellKnownResponse;
    }

    @Test
    public void getCredentialTypesTest() throws Exception{
        IssuerSupportedCredentialsResponse credentialTypesResponse = new IssuerSupportedCredentialsResponse();
        credentialTypesResponse.setSupportedCredentials(List.of(getCredentialSupportedResponse("credentialType1"),
                getCredentialSupportedResponse("credentialType2")));
        credentialTypesResponse.setAuthorizationEndPoint("authorization-endpoint");
        Mockito.when(issuersService.getCredentialsSupported("Issuer1", null))
                .thenReturn(credentialTypesResponse)
                .thenThrow(new ApiNotAccessibleException());
        Mockito.when(issuersService.getCredentialsSupported("invalidId", null))
                        .thenReturn(new IssuerSupportedCredentialsResponse());

        mockMvc.perform(get("/issuers/{issuer-id}/credentialTypes", "Issuer1").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response", Matchers.allOf(
                        Matchers.hasKey("authorization_endpoint"),
                        Matchers.hasKey("supportedCredentials")
                )))
                .andExpect(jsonPath("$.response.supportedCredentials", Matchers.everyItem(
                        Matchers.allOf(
                                Matchers.hasKey("format"),
                                Matchers.hasKey("id"),
                                Matchers.hasKey("scope"),
                                Matchers.hasKey("display"),
                                Matchers.hasKey("proof_types_supported"),
                                Matchers.hasKey("credential_definition")
                        )
                )));
        mockMvc.perform(get("/issuers/{issuer-id}/credentialTypes", "Issuer1").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is(API_NOT_ACCESSIBLE_EXCEPTION.getCode())))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is(API_NOT_ACCESSIBLE_EXCEPTION.getMessage())));

        mockMvc.perform(get("/issuers/{issuer-id}/credentialTypes", "invalidId").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is(INVALID_ISSUER_ID_EXCEPTION.getCode())))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is(INVALID_ISSUER_ID_EXCEPTION.getMessage())));
    }

    @Test
    public void generatePdfForVCTest() throws Exception {
        Mockito.when(issuersService.getIssuerConfig("Issuer1"))
                .thenReturn(getIssuerDTO("Issuer1"))
                .thenThrow(new ApiNotAccessibleException());

        Mockito.when(restApiClient.getApi(ArgumentMatchers.any(String.class), ArgumentMatchers.any()))
                .thenReturn(getCredentialIssuerWellKnownResponseDto("Issuer1",
                        List.of(getCredentialSupportedResponse("CredentialType1"))));


        Mockito.when(issuersService.generatePdfForVerifiableCredentials("accessToken",
                        getIssuerDTO("Issuer1"), getCredentialSupportedResponse("CredentialType1"),
                        "credential_endpoint"))
                .thenReturn(new ByteArrayInputStream("Mock Pdf".getBytes()))
                .thenThrow(new Exception());

        mockMvc.perform(get("/issuers/Issuer1/credentials/CredentialType1/download")
                        .header("Bearer", "accessToken")
                        .accept(MediaType.APPLICATION_PDF))
                .andExpect(status().isOk());

        mockMvc.perform(get("/issuers/Issuer1/credentials/CredentialType1/download")
                        .header("Bearer", "accessToken").accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is(API_NOT_ACCESSIBLE_EXCEPTION.getCode())))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is(API_NOT_ACCESSIBLE_EXCEPTION.getMessage())));
    }

    @Test
    public void getAllIssuersTest() throws Exception {
        IssuersDTO issuers = new IssuersDTO();
        issuers.setIssuers((List.of(getIssuerDTO("Issuer1"), getIssuerDTO("Issuer2"))));
        Mockito.when(issuersService.getAllIssuers(null))
                .thenReturn(issuers)
                .thenThrow(new ApiNotAccessibleException());

        IssuersDTO filteredIssuers = new IssuersDTO();
        filteredIssuers.setIssuers(issuers.getIssuers().stream().filter(issuer -> issuer.getDisplay().stream()
                        .anyMatch(displayDTO -> displayDTO.getTitle().toLowerCase().contains("Issuer1".toLowerCase())))
                .collect(Collectors.toList()));

        Mockito.when(issuersService.getAllIssuers("Issuer1"))
                .thenReturn(filteredIssuers)
                .thenThrow(new ApiNotAccessibleException());

        mockMvc.perform(get("/issuers").accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response.issuers", Matchers.everyItem(
                        Matchers.allOf(
                                Matchers.hasKey("credential_issuer"),
                                Matchers.hasKey("display"),
                                Matchers.hasKey("client_id"),
                                Matchers.hasKey(".well-known"),
                                Matchers.not(Matchers.hasKey("redirect_url")),
                                Matchers.not(Matchers.hasKey("authorization_endpoint")),
                                Matchers.not(Matchers.hasKey("token_endpoint")),
                                Matchers.not(Matchers.hasKey("credential_endpoint")),
                                Matchers.not(Matchers.hasKey("credential_audience")),
                                Matchers.not(Matchers.hasKey("additional_headers")),
                                Matchers.not(Matchers.hasKey("scopes_supported"))
                        )
                )));

        mockMvc.perform(get("/issuers?search=Issuer1").accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response.issuers", Matchers.everyItem(
                        Matchers.allOf(
                                Matchers.hasKey("credential_issuer"),
                                Matchers.hasKey("display"),
                                Matchers.hasKey("client_id"),
                                Matchers.hasKey(".well-known"),
                                Matchers.not(Matchers.hasKey("redirect_url")),
                                Matchers.not(Matchers.hasKey("authorization_endpoint")),
                                Matchers.not(Matchers.hasKey("token_endpoint")),
                                Matchers.not(Matchers.hasKey("credential_endpoint")),
                                Matchers.not(Matchers.hasKey("credential_audience")),
                                Matchers.not(Matchers.hasKey("additional_headers")),
                                Matchers.not(Matchers.hasKey("scopes_supported"))
                        )
                )));

        mockMvc.perform(get("/issuers").accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is(API_NOT_ACCESSIBLE_EXCEPTION.getCode())))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is(API_NOT_ACCESSIBLE_EXCEPTION.getMessage())));


        mockMvc.perform(get("/issuers?search=Issuer1").accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is(API_NOT_ACCESSIBLE_EXCEPTION.getCode())))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is(API_NOT_ACCESSIBLE_EXCEPTION.getMessage())));
    }

    @Test
    public void getIssuerConfigTest() throws Exception {
        Mockito.when(issuersService.getIssuerConfig("id1"))
                .thenReturn(getIssuerDTO("Issuer1"))
                .thenThrow(new ApiNotAccessibleException());
        Mockito.when(issuersService.getIssuerConfig("invalidId")).thenReturn(null);

        mockMvc.perform(get("/issuers/id1").accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isOk());

        mockMvc.perform(get("/issuers/invalidId").accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is(INVALID_ISSUER_ID_EXCEPTION.getCode())))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is(INVALID_ISSUER_ID_EXCEPTION.getMessage())));

        mockMvc.perform(get("/issuers/id1").accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors[0].errorCode", Matchers.is(API_NOT_ACCESSIBLE_EXCEPTION.getCode())))
                .andExpect(jsonPath("$.errors[0].errorMessage", Matchers.is(API_NOT_ACCESSIBLE_EXCEPTION.getMessage())));
    }

    @Test
    public void processOfflineTest() throws Exception {
        AttestationStatement attestationStatement = new AttestationStatement();
        Mockito.when(attestationOfflineVerify.parseAndVerify(Mockito.anyString())).thenReturn(attestationStatement);
        this.mockMvc.perform(post("/safetynet/offline/verify").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content("offlineStr"))
                .andExpect(status().isOk());
    }

    @Test
    public void processOfflineFailureTest() throws Exception {
        AttestationStatement attestationStatement = new AttestationStatement();
        Mockito.when(attestationOfflineVerify.parseAndVerify(Mockito.anyString())).thenThrow(new Exception("Exception"));
        this.mockMvc.perform(post("/safetynet/offline/verify").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content("offlineStr"))
                .andExpect(status().isOk());
    }

    @Test
    public void processOnlineTest() throws Exception {
        AttestationStatement attestationStatement = new AttestationStatement();
        Mockito.when(attestationOnlineVerify.parseAndVerify(Mockito.anyString())).thenReturn(attestationStatement);
        this.mockMvc.perform(post("/safetynet/online/verify").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content("offlineStr"))
                .andExpect(status().isOk());
    }

    @Test
    public void processOnlineFailureTest() throws Exception {
        AttestationStatement attestationStatement = new AttestationStatement();
        Mockito.when(attestationOnlineVerify.parseAndVerify(Mockito.anyString())).thenThrow(new Exception("Exception"));
        this.mockMvc.perform(post("/safetynet/online/verify").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content("offlineStr"))
                .andExpect(status().isOk());
    }

    /**
     * CREDENTIAL SHARE CONTROLLER TEST CASES
     */

    @Test
    @Ignore
    public void handleSubscribeEventTest() throws Exception {
        Event event = new Event();
        event.setId("id");
        event.setTransactionId("transId");
        EventModel eventModel = new EventModel();
        eventModel.setEvent(event);

        Mockito.when(credentialShareService.generateDocuments(Mockito.any())).thenReturn(true);

        this.mockMvc.perform(post("/v1/mimoto/credentialshare/callback/notify").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(JsonUtils.javaObjectToJsonString(eventModel)))
                .andExpect(status().isOk());
    }

    @Test
    public void requestTest() throws Exception {
        AppCredentialRequestDTO requestDTO = new AppCredentialRequestDTO();
        requestDTO.setUser("mono");
        requestDTO.setTransactionID("transactionId");
        requestDTO.setOtp("123456");
        requestDTO.setIndividualId("123456");
        requestDTO.setCredentialType("VERCRED");

        CredentialRequestResponseInnerResponseDTO dto = new CredentialRequestResponseInnerResponseDTO();
        dto.setRequestId("requestId");
        CredentialRequestResponseDTO response = new CredentialRequestResponseDTO();
        response.setResponse(dto);

        Mockito.when(restClientService.postApi(Mockito.any(), Mockito.anyString(), Mockito.anyString(),
                Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(response);

        Mockito.when(credentialShareService.generateDocuments(Mockito.any())).thenReturn(true);

        this.mockMvc.perform(post("/credentialshare/request").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(JsonUtils.javaObjectToJsonString(requestDTO)))
                .andExpect(status().isOk());
    }

    @Test
    public void requestStatusTest() throws Exception {

        ResponseWrapper<CredentialRequestStatusResponseDTO> responseWrapper = new ResponseWrapper<>();

        Mockito.when(restClientService.postApi(Mockito.any(), Mockito.anyString(), Mockito.anyString(),
                Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(responseWrapper);

        this.mockMvc.perform(get("/credentialshare/request/status/1234567890").accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isOk());
    }

    @Test
    public void downloadTest() throws Exception {

        CredentialDownloadRequestDTO requestDTO = new CredentialDownloadRequestDTO();
        requestDTO.setRequestId("requestId");
        requestDTO.setIndividualId("individualId");

        JsonNode credentialJSON = JsonNodeFactory.instance.objectNode();
        Mockito.when(utilities.getVC(Mockito.anyString())).thenReturn(credentialJSON);

        JsonNode decryptedCredentialJSON = JsonNodeFactory.instance.objectNode();
        Mockito.when(utilities.getDecryptedVC(Mockito.anyString())).thenReturn(decryptedCredentialJSON);

        JsonNode requestCredentialJSON = JsonNodeFactory.instance.objectNode();
        Mockito.when(utilities.getRequestVC(Mockito.anyString())).thenReturn(requestCredentialJSON);

        this.mockMvc.perform(post("/credentialshare/download").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(JsonUtils.javaObjectToJsonString(requestDTO)))
                .andExpect(status().isOk());

        Mockito.when(utilities.getDecryptedVC(Mockito.anyString())).thenReturn(null);

        this.mockMvc.perform(post("/credentialshare/download").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(JsonUtils.javaObjectToJsonString(requestDTO)))
                .andExpect(status().isNotFound());

        Mockito.when(utilities.getDecryptedVC(Mockito.anyString())).thenThrow(new IOException("Exception"));

        this.mockMvc.perform(post("/credentialshare/download").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(JsonUtils.javaObjectToJsonString(requestDTO)))
                .andExpect(status().isNotFound());
    }

    /**
     * IDP CONTROLLER TEST CASES
     */

    @Test
    public void otpRequestTest() throws Exception {
        BindingOtpInnerReqDto innerReqDto = new BindingOtpInnerReqDto();
        innerReqDto.setIndividualId("individualId");
        innerReqDto.setOtpChannels(Lists.newArrayList("EMAIL"));
        BindingOtpRequestDto requestDTO = new BindingOtpRequestDto(DateUtils.getUTCCurrentDateTimeString(), innerReqDto);


        ResponseWrapper<BindingOtpResponseDto> response = new ResponseWrapper<>();

        Mockito.when(restClientService.postApi(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.anyBoolean())).thenReturn(response).thenThrow(new BaseUncheckedException("Exception"));

        this.mockMvc.perform(post("/binding-otp").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(JsonUtils.javaObjectToJsonString(requestDTO)))
                .andExpect(status().isOk());

        this.mockMvc.perform(post("/binding-otp").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(JsonUtils.javaObjectToJsonString(requestDTO)))
                .andExpect(status().isBadRequest());
    }

    @Test
    public void walletBindingTest() throws Exception {
        WalletBindingInnerReq innerReqDto = new WalletBindingInnerReq();
        innerReqDto.setPublicKey("-----BEGIN RSA PUBLIC KEY-----\nMIICCgKCAgEAn6+frMlD7DQqbxZW943hRLBApDj1/lHIJdLYSKEGIfwhd58gc0Y4\n1q11mPnpv7gAZ/Wm0iOAkWSzcIWljXFmGnLrUrBsp4WYKdPjqn4tkrCOjiZa5RPk\nY03a40Kz1lx0W9f94Naozglf6KFUSq+qAwuC5kiPxaxsjFA/LWIP+zT2QX/MnrX9\nv7gt2g0BC4pQ01eTTzhhwO2A7k5z3ucsb56ohND4xdIsdCMm1IczBjW0URSO60Bb\n7m5dlO8BFHJ6inV8awO2KHoADbp3wZgid4KqLJ0eVGyNViVFzj4rxSxL3vcYbyKS\nORWSlPZIZL9ZWO1cyPO9+Wxu29IKj4DQEt8glgITlBZ4L29uT7gFPAbypSn/8SvU\nBrNno8+GIe9XWsrDTMT9dfLGzLUitF3A+wwVZuRVhCqYIisOOGuGE18YK0jmdk9l\n89OpK4PduGiUh66zZTcH3thdtaOz6jj+FLKMg2Q3gNqQ1Y0cezO175RNVVX1ffOu\n5qss1RWams5RAXDqqt/MhiopG3DhlyaSC4xdqei7SI8d+S4Bvflub9rypPnhW67g\nNhZvQDJ7Tb1AWHxKmU0wQvEMtwSm9xtsMs4bqotn2M/09BuRqbrhpvAfrfZArkVO\nv8eLXhtDvo2J9gRwHZIS/JZ1Fo+tep1QFHz1Lr5iGRqwLWQlGbKFuL0CAwEAAQ==\n-----END RSA PUBLIC KEY-----\n");
        innerReqDto.setIndividualId("individualId");
        WalletBindingRequestDTO requestDTO = new WalletBindingRequestDTO();
        requestDTO.setRequestTime(DateUtils.getUTCCurrentDateTimeString());
        requestDTO.setRequest(innerReqDto);

        ResponseWrapper<WalletBindingResponseDto> response = new ResponseWrapper<>();

        Mockito.when(restClientService.postApi(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.anyBoolean())).thenReturn(response).thenThrow(new BaseUncheckedException("Exception"));

        this.mockMvc.perform(post("/wallet-binding").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(JsonUtils.javaObjectToJsonString(requestDTO)))
                .andExpect(status().isOk());

        this.mockMvc.perform(post("/wallet-binding").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(JsonUtils.javaObjectToJsonString(requestDTO)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @Ignore
    public void linkTransactionTest() throws Exception {
        LinkTransactionRequestDto requestDTO = new LinkTransactionRequestDto();
        requestDTO.setRequestTime(DateUtils.getUTCCurrentDateTimeString());
        requestDTO.setLinkCode("linkcode");

        LinkTransactionResponseDto response = new LinkTransactionResponseDto();

        Mockito.when(restClientService.postApi(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.anyBoolean())).thenReturn(response).thenThrow(new BaseUncheckedException("Exception"));

        this.mockMvc.perform(post("/link-transaction").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(JsonUtils.javaObjectToJsonString(requestDTO)))
                .andExpect(status().isOk());

        this.mockMvc.perform(post("/link-transaction").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(JsonUtils.javaObjectToJsonString(requestDTO)))
                .andExpect(status().isOk());
    }

    @Test
    @Ignore
    public void idpAuthAndConsentTest() throws Exception {
        AuthAndConsentRequestDto innerDto = new AuthAndConsentRequestDto();
        innerDto.setLinkedTransactionId("LinkedTransactionId");
        innerDto.setIndividualId("individualId");
        innerDto.setLinkedTransactionId("LinkedTransactionId");
        innerDto.setAcceptedClaims(Lists.newArrayList("OTP"));
        IdpAuthChallangeDto challangeDto = new IdpAuthChallangeDto();
        challangeDto.setAuthFactorType("OTP");
        challangeDto.setChallenge("1234");
        innerDto.setChallengeList(Lists.newArrayList(challangeDto));
        IdpAuthAndConsentDto requestDto = new IdpAuthAndConsentDto();
        requestDto.setRequestTime(DateUtils.getUTCCurrentDateTimeString());
        requestDto.setRequest(innerDto);


        LinkedTransactionResponseDto resp = new LinkedTransactionResponseDto();
        resp.setLinkedTransactionId("linkedTransactionId");
        ResponseWrapper<LinkedTransactionResponseDto> responseWrapper = new ResponseWrapper<>();
        responseWrapper.setResponse(resp);

        Mockito.when(restClientService.postApi(Mockito.any(),
                        Mockito.any(), Mockito.any(), Mockito.anyBoolean())).thenReturn(responseWrapper)
                .thenReturn(responseWrapper).thenThrow(new ApisResourceAccessException("exception"));

        this.mockMvc.perform(post("/idp-auth-consent").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(JsonUtils.javaObjectToJsonString(requestDto)))
                .andExpect(status().isOk());

        this.mockMvc.perform(post("/idp-auth-consent").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(JsonUtils.javaObjectToJsonString(requestDto)))
                .andExpect(status().isOk());
    }

    @Test
    @Ignore
    public void idpAuthenticateTest() throws Exception {
        IdpAuthInternalRequestDto innerDto = new IdpAuthInternalRequestDto();
        innerDto.setLinkedTransactionId("LinkedTransactionId");
        innerDto.setIndividualId("individualId");
        IdpAuthChallangeDto challangeDto = new IdpAuthChallangeDto();
        challangeDto.setAuthFactorType("OTP");
        challangeDto.setChallenge("1234");
        innerDto.setChallengeList(Lists.newArrayList(challangeDto));
        IdpAuthRequestDto requestDto = new IdpAuthRequestDto();
        requestDto.setRequestTime(DateUtils.getUTCCurrentDateTimeString());
        requestDto.setRequest(innerDto);


        BindingOtpResponseDto responseDto = new BindingOtpResponseDto();
        responseDto.setTransactionId("1111111");
        ResponseWrapper<BindingOtpResponseDto> otpResponse = new ResponseWrapper<>();
        otpResponse.setResponse(responseDto);
        ResponseWrapper<BindingOtpResponseDto> otpResponse2 = new ResponseWrapper<>();
        ResponseWrapper<LinkedTransactionResponseDto> response = new ResponseWrapper<>();

        Mockito.when(restClientService.postApi(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.anyBoolean())).thenReturn(otpResponse).thenReturn(response).thenReturn(otpResponse2);

        this.mockMvc.perform(post("/idp-authenticate").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(JsonUtils.javaObjectToJsonString(requestDto)))
                .andExpect(status().isOk());

        this.mockMvc.perform(post("/idp-authenticate").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(JsonUtils.javaObjectToJsonString(requestDto)))
                .andExpect(status().isOk());
    }

    @Test
    @Ignore
    public void idpConsentTest() throws Exception {
        IdpConsentRequestDto innerDto = new IdpConsentRequestDto();
        innerDto.setLinkedTransactionId("LinkedTransactionId");
        innerDto.setAcceptedClaims(Lists.newArrayList("OTP"));
        IdpConsentDto requestDto = new IdpConsentDto();
        requestDto.setRequestTime(DateUtils.getUTCCurrentDateTimeString());
        requestDto.setRequest(innerDto);


        ResponseWrapper<LinkedTransactionResponseDto> response = new ResponseWrapper<>();

        Mockito.when(restClientService.postApi(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.anyBoolean())).thenReturn(response).thenThrow(new BaseUncheckedException("Exception"));

        this.mockMvc.perform(post("/idp-consent").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(JsonUtils.javaObjectToJsonString(requestDto)))
                .andExpect(status().isOk());

        this.mockMvc.perform(post("/idp-consent").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(JsonUtils.javaObjectToJsonString(requestDto)))
                .andExpect(status().isOk());
    }

    /**
     * RESIDENT CONTROLLER TEST CASES
     */
    @Test
    public void residentOtpRequestTest() throws Exception {
        AppOTPRequestDTO requestDTO = new AppOTPRequestDTO();
        requestDTO.setIndividualId("IndividualId");
        requestDTO.setIndividualIdType("UIN");
        requestDTO.setTransactionID("1234567890");
        requestDTO.setOtpChannel(Lists.newArrayList("EMAIL"));


        ResponseWrapper<CredentialRequestResponseDTO> response = new ResponseWrapper<>();

        Mockito.when(restClientService.postApi(Mockito.any(),
                Mockito.any(), Mockito.any(), Mockito.anyBoolean())).thenReturn(response);

        this.mockMvc.perform(post("/req/otp").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(JsonUtils.javaObjectToJsonString(requestDTO)))
                .andExpect(status().isOk());
    }

    @Test
    public void vidGenerateTest() throws Exception {
        AppVIDGenerateRequestDTO requestDTO = new AppVIDGenerateRequestDTO();
        requestDTO.setIndividualId("IndividualId");
        requestDTO.setIndividualIdType("UIN");
        requestDTO.setTransactionID("1234567890");
        requestDTO.setOtp("111111");


        ResponseWrapper<VIDGeneratorResponseDTO> response = new ResponseWrapper<>();

        Mockito.when(restClientService.postApi(Mockito.any(),
                Mockito.anyString(), Mockito.anyString(), Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(response);

        this.mockMvc.perform(post("/vid").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(JsonUtils.javaObjectToJsonString(requestDTO)))
                .andExpect(status().isOk());
    }

    @Test
    public void authLockTest() throws Exception {
        AuthLockRequestDTO requestDTO = new AuthLockRequestDTO();
        requestDTO.setIndividualId("IndividualId");
        requestDTO.setIndividualIdType("UIN");
        requestDTO.setTransactionID("1234567890");
        requestDTO.setOtp("111111");


        ResponseWrapper<AuthLockUnlockResponseDTO> response = new ResponseWrapper<>();

        Mockito.when(restClientService.postApi(Mockito.any(),
                Mockito.anyString(), Mockito.anyString(), Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(response);

        this.mockMvc.perform(post("/req/auth/lock").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(JsonUtils.javaObjectToJsonString(requestDTO)))
                .andExpect(status().isOk());
    }

    @Test
    public void authUnLockTest() throws Exception {
        AuthUnlockRequestDTO requestDTO = new AuthUnlockRequestDTO();
        requestDTO.setIndividualId("IndividualId");
        requestDTO.setIndividualIdType("UIN");
        requestDTO.setTransactionID("1234567890");
        requestDTO.setOtp("111111");


        ResponseWrapper<AuthLockUnlockResponseDTO> response = new ResponseWrapper<>();

        Mockito.when(restClientService.postApi(Mockito.any(),
                Mockito.anyString(), Mockito.anyString(), Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(response);

        this.mockMvc.perform(post("/req/auth/unlock").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(JsonUtils.javaObjectToJsonString(requestDTO)))
                .andExpect(status().isOk());
    }

    @Test
    public void individualIdOtpRequestTest() throws Exception {
        IndividualIdOtpRequestDTO requestDTO = new IndividualIdOtpRequestDTO();
        requestDTO.setAid("IndividualId");
        requestDTO.setOtpChannel(Lists.newArrayList("EMAIL"));
        requestDTO.setTransactionID("1234567890");

        OTPResponseDTO response = new OTPResponseDTO();

        Mockito.when(restClientService.postApi(Mockito.any(),
                Mockito.anyString(), Mockito.anyString(), Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(response);

        this.mockMvc.perform(post("/req/individualId/otp").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(JsonUtils.javaObjectToJsonString(requestDTO)))
                .andExpect(status().isOk());
    }

    @Test
    public void aidGetIndividualIdTest() throws Exception {
        AidStatusRequestDTO requestDTO = new AidStatusRequestDTO();
        requestDTO.setAid("IndividualId");
        requestDTO.setTransactionID("1234567890");
        requestDTO.setOtp("111111");

        ResponseWrapper<AidStatusResponseDTO> response = new ResponseWrapper<>();

        Mockito.when(restClientService.postApi(Mockito.any(),
                Mockito.anyString(), Mockito.anyString(), Mockito.any(), Mockito.any(), Mockito.any())).thenReturn(response);

        this.mockMvc.perform(post("/aid/get-individual-id").contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(JsonUtils.javaObjectToJsonString(requestDTO)))
                .andExpect(status().isOk());
    }
}
