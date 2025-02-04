package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import io.mosip.mimoto.service.IssuerWellknownService;
import io.mosip.mimoto.util.CredentialIssuerWellknownResponseValidator;
import io.mosip.mimoto.util.RestApiClient;
import jakarta.validation.Validator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
public class IssuerWellknownServiceImpl implements IssuerWellknownService {

    @Autowired
    private RestApiClient restApiClient;

    @Autowired
    private CredentialIssuerWellknownResponseValidator credentialIssuerWellknownResponseValidator;

    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    private Validator validator;


    @Override
    @Cacheable(value = "issuerWellknown", key = "{#credentialIssuerHost}")
    public CredentialIssuerWellKnownResponse getWellknown(String credentialIssuerHost) throws ApiNotAccessibleException, IOException, InvalidWellknownResponseException {
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
}
