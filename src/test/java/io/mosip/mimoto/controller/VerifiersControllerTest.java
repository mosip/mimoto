package io.mosip.mimoto.controller;

import io.mosip.mimoto.dto.openid.VerifierDTO;
import io.mosip.mimoto.dto.openid.VerifiersDTO;
import io.mosip.mimoto.service.impl.VerifierServiceImpl;
import org.hamcrest.Matchers;
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

import java.util.Collections;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = VerifiersController.class)
@AutoConfigureMockMvc(addFilters = false)
@EnableWebMvc
public class VerifiersControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private VerifierServiceImpl verifierService;


    @Test
    public void getAllTrustedVerifiers() throws Exception {
        VerifierDTO verifierDTO = VerifierDTO.builder()
                .clientId("test-clientId")
                .redirectUris(Collections.singletonList("https://test-redirectUri"))
                .responseUris(Collections.singletonList("https://test-responseUri")).build();

        VerifiersDTO trustedVerifiers = VerifiersDTO.builder()
                .verifiers(Collections.singletonList(verifierDTO)).build();

        Mockito.when(verifierService.getTrustedVerifiers())
                .thenReturn(trustedVerifiers);


        mockMvc.perform(get("/verifiers").accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.response.verifiers", Matchers.everyItem(
                        Matchers.allOf(
                                Matchers.hasKey("client_id"),
                                Matchers.hasKey("redirect_uris"),
                                Matchers.hasKey("response_uris")
                        )
                )));
    }
}
