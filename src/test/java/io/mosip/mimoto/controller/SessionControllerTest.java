package io.mosip.mimoto.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import jakarta.servlet.http.HttpServletRequest;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = SessionController.class)
@AutoConfigureMockMvc(addFilters = false)
@EnableWebMvc
public class SessionControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @InjectMocks
    private SessionController sessionController;

    @MockBean
    private HttpServletRequest request;

    @MockBean
    private ObjectMapper objectMapper;

    @Test
    public void shouldReturnSuccessResponseForValidSessionAndUserId() throws Exception {
        MockHttpSession mockSession = new MockHttpSession();
        mockSession.setAttribute("userId", "123");

        this.mockMvc.perform(get("/session/status").session(mockSession).accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().string("The session is valid and active"));
    }

    @Test
    public void shouldReturnProperErrorResponseWhenSessionIsNull() throws Exception {
        this.mockMvc.perform(get("/session/status").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.errorCode").value("RESIDENT-APP-045"))
                .andExpect(jsonPath("$.errorMessage").value("The session is invalid or expired due to inactivity"));
    }


    @Test
    public void shouldReturnProperErrorResponseWhenTheUserIdInSessionIsNull() throws Exception {
        MockHttpSession mockSession = new MockHttpSession();

        this.mockMvc.perform(get("/session/status").session(mockSession).accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.errorCode").value("RESIDENT-APP-045"))
                .andExpect(jsonPath("$.errorMessage").value("The session is invalid or expired due to inactivity"));
    }
}
