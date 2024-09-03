package io.mosip.mimoto.controller;

import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.service.impl.IssuersServiceImpl;
import org.hamcrest.Matchers;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.skyscreamer.jsonassert.JSONAssert;
import org.skyscreamer.jsonassert.JSONCompareMode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.ResourceUtils;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.io.File;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static io.mosip.mimoto.exception.PlatformErrorMessages.API_NOT_ACCESSIBLE_EXCEPTION;
import static io.mosip.mimoto.exception.PlatformErrorMessages.INVALID_ISSUER_ID_EXCEPTION;
import static io.mosip.mimoto.util.TestUtilities.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = IssuersController.class)
@AutoConfigureMockMvc(addFilters = false)
@EnableWebMvc
public class IssuersControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private IssuersServiceImpl issuersService;


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
    public void getIssuerWellknownTest() throws Exception {
        String issuerId = "id1";
        File file = ResourceUtils.getFile(ResourceUtils.CLASSPATH_URL_PREFIX + "responses/expectedWellknown.json");
        String expectedCredentialIssuerWellknownResponse = new String(Files.readAllBytes(file.toPath()));
        CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse = getCredentialIssuerWellKnownResponseDto(issuerId, Map.of("CredentialType1", getCredentialSupportedResponse("Credential1")));
        Mockito.when(issuersService.getIssuerWellknown(issuerId)).thenReturn(credentialIssuerWellKnownResponse);


        String actualResponse = mockMvc.perform(get("/issuers/" + issuerId + "/.well-known").accept(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();


        JSONAssert.assertEquals(new JSONObject(expectedCredentialIssuerWellknownResponse), new JSONObject(actualResponse), JSONCompareMode.LENIENT);

    }

}
