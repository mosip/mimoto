package io.mosip.mimoto.controller;

import com.google.common.collect.Lists;
import io.mosip.kernel.core.util.JsonUtils;
import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.exception.BaseUncheckedException;
import io.mosip.mimoto.service.RestClientService;
import io.mosip.mimoto.service.impl.CredentialServiceImpl;
import io.mosip.mimoto.service.impl.IdpServiceImpl;
import io.mosip.mimoto.service.impl.IssuersServiceImpl;
import io.mosip.mimoto.util.DateUtils;
import io.mosip.mimoto.util.JoseUtil;
import io.mosip.mimoto.util.RequestValidator;
import io.mosip.mimoto.util.RestApiClient;
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
@SpringBootTest(classes = IdpController.class)
@AutoConfigureMockMvc(addFilters = false)
@EnableWebMvc
public class IdpControllerTest {


    @Autowired
    private MockMvc mockMvc;

    @MockBean
    public RestApiClient restApiClient;

    @MockBean
    private JoseUtil joseUtil;

    @MockBean
    RequestValidator requestValidator;

    @MockBean
    public RestClientService<Object> restClientService;

    @MockBean
    private IssuersServiceImpl issuersService;

    @MockBean
    private IdpServiceImpl idpService;

    @MockBean
    private CredentialServiceImpl credentialService;

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

}