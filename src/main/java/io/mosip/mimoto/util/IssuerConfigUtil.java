package io.mosip.mimoto.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.mimoto.AuthorizationServerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.AuthorizationServerWellknownResponseException;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import java.io.IOException;
import java.util.Set;


@Service
@Slf4j
public class IssuerConfigUtil {

    @Autowired
    private RestApiClient restApiClient;

    @Autowired
    private CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator;

    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    private Validator validator;


    @Cacheable(value = "issuerWellknown", key = "#p0")
    public CredentialIssuerWellKnownResponse getIssuerWellknown(String credentialIssuerHost) throws ApiNotAccessibleException, IOException, InvalidWellknownResponseException {
        try {
            String wellknownEndpoint = credentialIssuerHost + "/.well-known/openid-credential-issuer";
            String wellknownResponse = restApiClient.getApi(wellknownEndpoint, String.class);
            if (wellknownResponse == null) {
                throw new ApiNotAccessibleException();
            }
            CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse = objectMapper.readValue(wellknownResponse, CredentialIssuerWellKnownResponse.class);
            credentialIssuerWellknownResponseValidator.validate(credentialIssuerWellKnownResponse, validator);
            return credentialIssuerWellKnownResponse;
        } catch (JsonProcessingException | ApiNotAccessibleException |
                 InvalidWellknownResponseException e) {
            throw e;
        }
    }

    @Cacheable(value = "authServerWellknown", key = "#p0")
    public AuthorizationServerWellKnownResponse getAuthServerWellknown(String authorizationServerHostUrl) throws AuthorizationServerWellknownResponseException {
        try {
            String wellknownEndpoint = authorizationServerHostUrl + "/.well-known/oauth-authorization-server";
            log.debug("fetching Authorization Server Wellknown by calling :: " + wellknownEndpoint);
            String wellknownResponse = restApiClient.getApi(wellknownEndpoint, String.class);
            if (wellknownResponse == null) {
                throw new Exception("well-known api is not accessible");
            }
            AuthorizationServerWellKnownResponse authorizationServerWellKnownResponse = objectMapper.readValue(wellknownResponse, AuthorizationServerWellKnownResponse.class);
            validate(authorizationServerWellKnownResponse);

            return authorizationServerWellKnownResponse;
        } catch (Exception e) {
            throw new AuthorizationServerWellknownResponseException(e.toString());
        }
    }

    public void validate(AuthorizationServerWellKnownResponse response) throws Exception {
        try {
            ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
            Validator validator = factory.getValidator();
            Set<ConstraintViolation<AuthorizationServerWellKnownResponse>> violations = validator.validate(response);
            if (!violations.isEmpty()) {
                StringBuilder sb = new StringBuilder("Validation failed:");
                for (ConstraintViolation<AuthorizationServerWellKnownResponse> violation : violations) {
                    sb.append("\n").append(violation.getPropertyPath()).append(": ").append(violation.getMessage());
                }

                throw new Exception(sb.toString());
            }
        } catch (Exception e) {
            throw new Exception(e.toString());
        }
    }
}
