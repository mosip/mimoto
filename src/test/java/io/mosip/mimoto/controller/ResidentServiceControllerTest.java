package io.mosip.mimoto.controller;

import com.google.common.collect.Lists;
import io.mosip.kernel.core.util.JsonUtils;
import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.dto.mimoto.AidStatusRequestDTO;
import io.mosip.mimoto.dto.mimoto.AppOTPRequestDTO;
import io.mosip.mimoto.dto.mimoto.AppVIDGenerateRequestDTO;
import io.mosip.mimoto.dto.mimoto.IndividualIdOtpRequestDTO;
import io.mosip.mimoto.dto.resident.*;
import io.mosip.mimoto.service.RestClientService;
import io.mosip.mimoto.util.RequestValidator;
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

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


@RunWith(SpringRunner.class)
@SpringBootTest(classes = ResidentServiceController.class)
@AutoConfigureMockMvc(addFilters = false)
@EnableWebMvc
public class ResidentServiceControllerTest {

    @MockBean
    public RestClientService<Object> restClientService;

    @MockBean
    public RequestValidator requestValidator;

    @Autowired
    private MockMvc mockMvc;

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