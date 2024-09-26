package io.mosip.mimoto.controller;

import io.mosip.mimoto.config.InjiConfiguration;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.skyscreamer.jsonassert.JSONAssert;
import org.skyscreamer.jsonassert.JSONCompareMode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.ResourceUtils;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.io.File;
import java.nio.file.Files;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = {CommonInjiController.class, InjiConfiguration.class})
@AutoConfigureMockMvc(addFilters = false)
@EnableWebMvc
public class InjiControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    public void getAllPropertiesTest() throws Exception {
        File file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "responses/InjiConfig.json");
        String expectedResponse = new String(Files.readAllBytes(file.toPath()));

        String actualResponse = this.mockMvc.perform(get("/allProperties")
                        .accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        JSONAssert.assertEquals(expectedResponse, actualResponse, JSONCompareMode.LENIENT);

    }

}
