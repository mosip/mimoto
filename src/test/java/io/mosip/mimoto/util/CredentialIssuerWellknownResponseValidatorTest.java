package io.mosip.mimoto.util;

import io.mosip.mimoto.dto.BackgroundImageDTO;
import io.mosip.mimoto.dto.mimoto.CredentialDefinitionResponseDto;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.CredentialSupportedDisplayResponse;
import io.mosip.mimoto.dto.mimoto.CredentialsSupportedResponse;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static io.mosip.mimoto.util.TestUtilities.getCredentialIssuerWellKnownResponseDto;
import static io.mosip.mimoto.util.TestUtilities.getCredentialSupportedResponse;
import static org.junit.Assert.assertThrows;

public class CredentialIssuerWellknownResponseValidatorTest {

    @Autowired
    private Validator validator;

    @BeforeEach
    void setUp() {
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @Test
    public void shouldThrowExceptionWhenCredentialIssuerIsMissingInCredentialIssuerWellknownResponse() throws ApiNotAccessibleException {
        CredentialIssuerWellKnownResponse response = getCredentialIssuerWellKnownResponseDto("Issuer1",
                Map.of("CredentialType1", getCredentialSupportedResponse("CredentialType1")));

        response.setCredentialIssuer("");
        response.setCredentialEndPoint("http://example.com");

        CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator = new CredentialIssuerWellknownResponseValidator();
        InvalidWellknownResponseException invalidWellknownResponseException = assertThrows(InvalidWellknownResponseException.class, () ->
                credentialIssuerWellknownResponseValidator.validate(response, validator));
        Assertions.assertEquals("RESIDENT-APP-041", invalidWellknownResponseException.getErrorCode());
        Assertions.assertTrue(invalidWellknownResponseException.getMessage().contains("credentialIssuer: must not be blank"), "Exception message should indicate the missing 'credentialIssuer'");
    }

    @Test
    public void shouldThrowExceptionWhenCredentialEndpointIsIncorrectInCredentialIssuerWellknownResponse() throws ApiNotAccessibleException {
        CredentialIssuerWellKnownResponse response = getCredentialIssuerWellKnownResponseDto("Issuer1",
                Map.of("CredentialType1", getCredentialSupportedResponse("CredentialType1")));

        response.setCredentialEndPoint("http://example.com"); // Incorrect because it does not end with "/credential"

        CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator = new CredentialIssuerWellknownResponseValidator();
        InvalidWellknownResponseException invalidWellknownResponseException = assertThrows(InvalidWellknownResponseException.class, () ->
                credentialIssuerWellknownResponseValidator.validate(response, validator));
        Assertions.assertEquals("RESIDENT-APP-041", invalidWellknownResponseException.getErrorCode());
        Assertions.assertTrue(invalidWellknownResponseException.getMessage().contains("credentialEndPoint: must match \"https?://.*?/credential$\""), "Exception message should indicate the incorrect 'credentialEndpoint'");
    }

    @Test
    public void shouldThrowExceptionWhenAuthorizationServersIsEmpty() {
        CredentialIssuerWellKnownResponse response = getCredentialIssuerWellKnownResponseDto("Issuer1",
                Map.of("CredentialType1", getCredentialSupportedResponse("CredentialType1")));

        response.setCredentialIssuer("https://valid.url/credential");
        response.setAuthorizationServers(Collections.emptyList());  // Invalid empty list

        CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator = new CredentialIssuerWellknownResponseValidator();
        InvalidWellknownResponseException invalidWellknownResponseException = assertThrows(InvalidWellknownResponseException.class, () ->
                credentialIssuerWellknownResponseValidator.validate(response, validator));
        Assertions.assertEquals("RESIDENT-APP-041", invalidWellknownResponseException.getErrorCode());
        Assertions.assertTrue(invalidWellknownResponseException.getMessage().contains("authorizationServers: must not be empty"), "Exception message should indicate 'authorizationServers' cannot be empty");
    }

    @Test
    public void shouldThrowExceptionWhenFormatIsMissingInCredentialsSupported() {
        CredentialIssuerWellKnownResponse response = getCredentialIssuerWellKnownResponseDto("Issuer1",
                Map.of("CredentialType1", new CredentialsSupportedResponse()));  // `format` is not set, default is null

        response.getCredentialConfigurationsSupported().get("CredentialType1").setFormat(null);

        CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator = new CredentialIssuerWellknownResponseValidator();
        InvalidWellknownResponseException invalidWellknownResponseException = assertThrows(InvalidWellknownResponseException.class, () ->
                credentialIssuerWellknownResponseValidator.validate(response, validator));
        Assertions.assertEquals("RESIDENT-APP-041", invalidWellknownResponseException.getErrorCode());
        Assertions.assertTrue(invalidWellknownResponseException.getMessage().contains("format: Format must not be blank"), "Exception message should indicate 'format' must not be blank");
    }

    @Test
    public void shouldThrowExceptionWhenCredentialDefinitionTypeIsEmpty() {
        CredentialIssuerWellKnownResponse response = getCredentialIssuerWellKnownResponseDto("Issuer1",
                Map.of("CredentialType1", getCredentialSupportedResponse("CredentialType1")));
        response.getCredentialConfigurationsSupported().get("CredentialType1").getCredentialDefinition().setType(Collections.emptyList());  // Invalid empty list

        CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator = new CredentialIssuerWellknownResponseValidator();
        InvalidWellknownResponseException invalidWellknownResponseException = assertThrows(InvalidWellknownResponseException.class, () ->
                credentialIssuerWellknownResponseValidator.validate(response, validator));
        Assertions.assertEquals("RESIDENT-APP-041", invalidWellknownResponseException.getErrorCode());
        Assertions.assertTrue(invalidWellknownResponseException.getMessage().contains("type: must not be empty"), "Exception message should indicate 'type' must not be empty");
    }

    @Test
    public void shouldThrowExceptionWhenLogoUrlIsInvalid() {
        CredentialIssuerWellKnownResponse response = getCredentialIssuerWellKnownResponseDto("Issuer1",
                Map.of("CredentialType1", getCredentialSupportedResponse("CredentialType1")));
        response.getCredentialConfigurationsSupported().get("CredentialType1").getDisplay().getFirst().getLogo().setUrl("ftp//invalid-url");  // Invalid URL
        CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator = new CredentialIssuerWellknownResponseValidator();
        InvalidWellknownResponseException invalidWellknownResponseException = assertThrows(InvalidWellknownResponseException.class, () ->
                credentialIssuerWellknownResponseValidator.validate(response, validator));
        Assertions.assertEquals("RESIDENT-APP-041", invalidWellknownResponseException.getErrorCode());
        System.out.println(invalidWellknownResponseException.getMessage());
        Assertions.assertTrue(invalidWellknownResponseException.getMessage().contains("logo.url: must be a valid URL"), "Exception message should indicate 'logo.url' must be a valid URL");
    }

    @Test
    public void shouldThrowExceptionWhenBackgroundImageUrlIsInvalid() {
        CredentialIssuerWellKnownResponse response = getCredentialIssuerWellKnownResponseDto("Issuer1",
                Map.of("CredentialType1", getCredentialSupportedResponse("CredentialType1")));

        response.getCredentialConfigurationsSupported().get("CredentialType1").getDisplay().getFirst().setBackgroundImage(new BackgroundImageDTO("local//imgbasebase64"));

        CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator = new CredentialIssuerWellknownResponseValidator();
        InvalidWellknownResponseException invalidWellknownResponseException = assertThrows(InvalidWellknownResponseException.class, () ->
                credentialIssuerWellknownResponseValidator.validate(response, validator));
        System.out.println(invalidWellknownResponseException.getMessage());
        Assertions.assertEquals("RESIDENT-APP-041", invalidWellknownResponseException.getErrorCode());
        Assertions.assertTrue(invalidWellknownResponseException.getMessage().contains("backgroundImage.uri: must be a valid URL"), "Exception message should indicate 'background_image.uri' must be a valid URL");
    }

    @Test
    public void shouldDetectMissingMandatoryFields() {

        CredentialIssuerWellKnownResponse response = getCredentialIssuerWellKnownResponseDto("Issuer1",
                Map.of("CredentialType1", getCredentialSupportedResponse("CredentialType1")));
        response.setCredentialEndPoint(null);
        response.setCredentialConfigurationsSupported(null);
        response.setAuthorizationServers(null);
        response.setCredentialIssuer(null);
        CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator = new CredentialIssuerWellknownResponseValidator();
        InvalidWellknownResponseException invalidWellknownResponseException = assertThrows(InvalidWellknownResponseException.class, () ->
                credentialIssuerWellknownResponseValidator.validate(response, validator));
        Assertions.assertEquals("RESIDENT-APP-041", invalidWellknownResponseException.getErrorCode());
        Assertions.assertTrue(invalidWellknownResponseException.getMessage().contains("authorizationServers: must not be empty"));
        Assertions.assertTrue(invalidWellknownResponseException.getMessage().contains("credentialIssuer: must not be blank"));
        Assertions.assertTrue(invalidWellknownResponseException.getMessage().contains("credentialConfigurationsSupported: must not be empty"));
        Assertions.assertTrue(invalidWellknownResponseException.getMessage().contains("credentialEndPoint: must not be blank"));

    }

    @Test
    public void shouldDetectMissingMandatoryFieldsOfCredentialSupportedResponse() {

        CredentialIssuerWellKnownResponse response = getCredentialIssuerWellKnownResponseDto("Issuer1",
                Map.of("CredentialType1", getCredentialSupportedResponse("CredentialType1")));
        response.getCredentialConfigurationsSupported().get("CredentialType1").setFormat(null);
        response.getCredentialConfigurationsSupported().get("CredentialType1").setScope(null);
        response.getCredentialConfigurationsSupported().get("CredentialType1").setDisplay(null);
        response.getCredentialConfigurationsSupported().get("CredentialType1").setProofTypesSupported(null);
        response.getCredentialConfigurationsSupported().get("CredentialType1").setCredentialDefinition(null);
        CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator = new CredentialIssuerWellknownResponseValidator();
        InvalidWellknownResponseException invalidWellknownResponseException = assertThrows(InvalidWellknownResponseException.class, () ->
                credentialIssuerWellknownResponseValidator.validate(response, validator));
        Assertions.assertEquals("RESIDENT-APP-041", invalidWellknownResponseException.getErrorCode());
        Assertions.assertTrue(invalidWellknownResponseException.getMessage().contains("format: Format must not be blank"));
        Assertions.assertTrue(invalidWellknownResponseException.getMessage().contains("scope: Scope must not be blank"));
        Assertions.assertTrue(invalidWellknownResponseException.getMessage().contains("proofTypesSupported: Proof types supported must not be empty"));
        Assertions.assertTrue(invalidWellknownResponseException.getMessage().contains("credentialDefinition: must not be null"));
        Assertions.assertTrue(invalidWellknownResponseException.getMessage().contains("display: Display information must not be empty"));

    }

    @Test
    public void shouldDetectMissingProofAlgorithmsSupported() {
        CredentialIssuerWellKnownResponse response = getCredentialIssuerWellKnownResponseDto("Issuer1",
                Map.of("CredentialType1", getCredentialSupportedResponse("CredentialType1")));
        response.getCredentialConfigurationsSupported().get("CredentialType1").getProofTypesSupported().get("jwt");
        CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator = new CredentialIssuerWellknownResponseValidator();
        InvalidWellknownResponseException invalidWellknownResponseException = assertThrows(InvalidWellknownResponseException.class, () ->
                credentialIssuerWellknownResponseValidator.validate(response, validator));
        Assertions.assertTrue(invalidWellknownResponseException.getMessage().contains("proofSigningAlgValuesSupported: must not be null"));
    }

    @Test
    public void shouldDetectMissingMandatoryFieldsOfCredentialSupportedDisplayResponse() {
        // Create a new response object with nested display response details
        CredentialIssuerWellKnownResponse response = getCredentialIssuerWellKnownResponseDto("Issuer1",
                Map.of("CredentialType1", getCredentialSupportedResponse("CredentialType1")));
        List<CredentialSupportedDisplayResponse> credentialSupportedDisplayResponseList = new ArrayList<>();
        CredentialSupportedDisplayResponse credentialSupportedDisplayResponse = new CredentialSupportedDisplayResponse();
        credentialSupportedDisplayResponse.setLogo(null);
        credentialSupportedDisplayResponse.setName(null);
        credentialSupportedDisplayResponse.setLocale(null);
        credentialSupportedDisplayResponse.setTextColor(null);
        credentialSupportedDisplayResponse.setBackgroundColor(null);
        credentialSupportedDisplayResponse.setBackgroundImage(null);
        credentialSupportedDisplayResponseList.add(credentialSupportedDisplayResponse);
        response.getCredentialConfigurationsSupported().get("CredentialType1").setDisplay(credentialSupportedDisplayResponseList);

        CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator = new CredentialIssuerWellknownResponseValidator();
        InvalidWellknownResponseException invalidWellknownResponseException = assertThrows(InvalidWellknownResponseException.class, () ->
                credentialIssuerWellknownResponseValidator.validate(response, validator)
        );
        Assertions.assertTrue(invalidWellknownResponseException.getMessage().contains("name: must not be blank"));
        Assertions.assertTrue(invalidWellknownResponseException.getMessage().contains("locale: must not be blank"));
        Assertions.assertTrue(invalidWellknownResponseException.getMessage().contains("backgroundImage: must not be null"));
        Assertions.assertTrue(invalidWellknownResponseException.getMessage().contains("backgroundColor: must not be blank"));
        Assertions.assertTrue(invalidWellknownResponseException.getMessage().contains("textColor: must not be blank"));
    }

    @Test
    public void shouldDetectMissingMandatoryFieldsOfCredentialDefinitionResponseDtoResponse() {
        CredentialIssuerWellKnownResponse response = getCredentialIssuerWellKnownResponseDto("Issuer1",
                Map.of("CredentialType1", getCredentialSupportedResponse("CredentialType1")));
        CredentialDefinitionResponseDto credentialDefinitionResponseDto=new CredentialDefinitionResponseDto();
        credentialDefinitionResponseDto.setCredentialSubject(null);
        credentialDefinitionResponseDto.setType(null);
        response.getCredentialConfigurationsSupported().get("CredentialType1").setCredentialDefinition(credentialDefinitionResponseDto);

        CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator = new CredentialIssuerWellknownResponseValidator();
        InvalidWellknownResponseException invalidWellknownResponseException = assertThrows(InvalidWellknownResponseException.class, () ->
                credentialIssuerWellknownResponseValidator.validate(response, validator)
        );
        Assertions.assertTrue(invalidWellknownResponseException.getMessage().contains("type: must not be empty"));
        Assertions.assertTrue(invalidWellknownResponseException.getMessage().contains("credentialSubject: must not be empty"));
    }
}
