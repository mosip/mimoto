package io.mosip.mimoto.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.service.impl.IssuersServiceImpl;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.validation.beanvalidation.LocalValidatorFactoryBean;
import java.util.List;

import static io.mosip.mimoto.util.TestUtilities.*;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = {IssuersValidationConfig.class, LocalValidatorFactoryBean.class, ObjectMapper.class})
public class IssuersValidationConfigTest {

    @Autowired
    private IssuersValidationConfig issuersValidationConfig;

    @MockBean
    private IssuersServiceImpl issuersService;

    IssuersDTO issuers = new IssuersDTO();

    @Test
    public void shouldNotThrowAnyExceptionForValidIssuersConfig() {
        try {
            issuers.setIssuers(List.of(getIssuerConfigDTO("Issuer8"), getIssuerConfigDTO("Issuer7")));
            when(issuersService.getAllIssuers()).thenReturn(issuers);

            issuersValidationConfig.run(mock(ApplicationArguments.class));
        } catch (Exception e) {
            Assert.fail("Exception message: " + e.getMessage());
        }
    }

    @Test
    public void shouldThrowExceptionIfTheFieldValuesOfIssuerAreNotSatisfyingNotBlankAnnotation() {
        try {
            issuers.setIssuers(List.of(getIssuerConfigDTOWithInvalidFieldValues("Issuer1", true, false), getIssuerConfigDTOWithInvalidFieldValues("Issuer2",true,false)));
            when(issuersService.getAllIssuers()).thenReturn(issuers);

            issuersValidationConfig.run(mock(ApplicationArguments.class));
        } catch (Exception exception) {
            String expectedErrorMsg = "\n\nValidation failed in Mimoto-issuers-config.json:\nErrors for issuer at index: 0 with issuerId - \n- authorization_audience must not be blank\n- client_alias must not be blank\n- client_id must not be blank\n- credential_issuer must not be blank\n- credential_issuer_host must not be blank\n- display[0].description must not be blank\n- display[0].language must not be blank\n- display[0].logo.url must be a valid URL\n- display[0].name must not be blank\n- display[0].title must not be blank\n- enabled must not be blank\n- issuer_id must not be blank\n- protocol must not be blank\n- proxy_token_endpoint must not be blank\n- redirect_uri must not be blank\n- token_endpoint must not be blank\n- wellknown_endpoint must not be blank\nErrors for issuer at index: 1 with issuerId - \n- authorization_audience must not be blank\n- client_alias must not be blank\n- client_id must not be blank\n- credential_issuer must not be blank\n- credential_issuer_host must not be blank\n- display[0].description must not be blank\n- display[0].language must not be blank\n- display[0].logo.url must be a valid URL\n- display[0].name must not be blank\n- display[0].title must not be blank\n- enabled must not be blank\n- issuer_id must not be blank\n- protocol must not be blank\n- proxy_token_endpoint must not be blank\n- redirect_uri must not be blank\n- token_endpoint must not be blank\n- wellknown_endpoint must not be blank\n- Duplicate value found for the issuerId. More than one issuer is having the same issuerId\n";
            String actualErrorMsg = exception.getMessage();

            assertEquals(expectedErrorMsg, actualErrorMsg);
        }
    }

    @Test
    public void shouldThrowExceptionIfTheFieldValuesOfIssuerAreNotSatisfyingUrlAnnotation() {
        try {
            issuers.setIssuers(List.of(getIssuerConfigDTOWithInvalidFieldValues("Issuer1", false, true), getIssuerConfigDTOWithInvalidFieldValues("Issuer2",false,true)));
            when(issuersService.getAllIssuers()).thenReturn(issuers);

            issuersValidationConfig.run(mock(ApplicationArguments.class));
        } catch (Exception exception) {
            String expectedErrorMsg = "\n\nValidation failed in Mimoto-issuers-config.json:\nErrors for issuer at index: 0 with issuerId - Issuer1id\n- credential_issuer_host must be a valid URL\n- proxy_token_endpoint must be a valid URL\n- token_endpoint must be a valid URL\n- wellknown_endpoint must be a valid URL\n- TokenEndpoint does not match with the credential issuerId\nErrors for issuer at index: 1 with issuerId - Issuer2id\n- credential_issuer_host must be a valid URL\n- proxy_token_endpoint must be a valid URL\n- token_endpoint must be a valid URL\n- wellknown_endpoint must be a valid URL\n- TokenEndpoint does not match with the credential issuerId\n";
            String actualErrorMsg = exception.getMessage();

            assertEquals(expectedErrorMsg, actualErrorMsg);
        }
    }
}