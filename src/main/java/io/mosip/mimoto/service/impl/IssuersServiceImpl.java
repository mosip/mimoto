package io.mosip.mimoto.service.impl;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.CredentialsSupportedResponse;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.InvalidIssuerIdException;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.util.CredentialIssuerWellknownResponseValidator;
import io.mosip.mimoto.util.LoggerUtil;
import io.mosip.mimoto.util.RestApiClient;
import io.mosip.mimoto.util.Utilities;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;


@Service
public class IssuersServiceImpl implements IssuersService {
    private final Logger logger = LoggerUtil.getLogger(IssuersServiceImpl.class);

    @Autowired
    private Utilities utilities;

    @Autowired
    private Validator validator;

    @Autowired
    private RestApiClient restApiClient;

    @Autowired
    private ObjectMapper objectMapper;


    @Override
    public IssuersDTO getAllIssuers(String search) throws ApiNotAccessibleException{
        IssuersDTO issuers;
        String issuersConfigJsonValue = utilities.getIssuersConfigJsonValue();
        if (issuersConfigJsonValue == null) {
            throw new ApiNotAccessibleException();
        }
        Gson gsonWithIssuerDataOnlyFilter = new GsonBuilder().excludeFieldsWithoutExposeAnnotation().create();
        issuers = gsonWithIssuerDataOnlyFilter.fromJson(issuersConfigJsonValue, IssuersDTO.class);
        List<IssuerDTO> enabledIssuers = issuers.getIssuers().stream()
                .filter(issuer -> "true".equals(issuer.getEnabled()))
                .collect(Collectors.toList());
        issuers.setIssuers(enabledIssuers);

        // Filter issuers list with search string
        if (!StringUtils.isEmpty(search)) {
            List<IssuerDTO> filteredIssuers = issuers.getIssuers().stream()
                    .filter(issuer -> issuer.getDisplay().stream()
                            .anyMatch(displayDTO -> displayDTO.getTitle().toLowerCase().contains(search.toLowerCase())))
                    .collect(Collectors.toList());
            issuers.setIssuers(filteredIssuers);
            return issuers;
        }
        return issuers;
    }

    @Override
    public IssuersDTO getAllIssuersWithAllFields() throws ApiNotAccessibleException, IOException {
        IssuersDTO issuers;
        String issuersConfigJsonValue = utilities.getIssuersConfigJsonValue();
        if (issuersConfigJsonValue == null) {
            throw new ApiNotAccessibleException();
        }
        Gson gsonWithIssuerDataOnlyFilter = new GsonBuilder().create();
        issuers = gsonWithIssuerDataOnlyFilter.fromJson(issuersConfigJsonValue, IssuersDTO.class);

        return issuers;
    }


    @Override
    public IssuerDTO getIssuerConfig(String issuerId) throws ApiNotAccessibleException, IOException {
        IssuerDTO issuerDTO = null;
        String issuersConfigJsonValue = utilities.getIssuersConfigJsonValue();
        if (issuersConfigJsonValue == null) {
            throw new ApiNotAccessibleException();
        }
        IssuersDTO issuers = new Gson().fromJson(issuersConfigJsonValue, IssuersDTO.class);
        Optional<IssuerDTO> issuerConfigResp = issuers.getIssuers().stream()
                .filter(issuer -> issuer.getCredential_issuer().equals(issuerId))
                .findFirst();
        if (issuerConfigResp.isPresent())
            issuerDTO = issuerConfigResp.get();
        else
            throw new InvalidIssuerIdException();
        return issuerDTO;
    }

    @Override
    public CredentialIssuerWellKnownResponse getIssuerWellknown(String issuerId) throws ApiNotAccessibleException, IOException {
        return getAllIssuersWithAllFields().getIssuers().stream()
                .filter(issuer -> issuer.getCredential_issuer().equals(issuerId))
                .findFirst()
                .map(issuerDTO -> {
                    String wellknownResponse = restApiClient.getApi(issuerDTO.getWellKnownEndpoint(), String.class);
                    try {
                        CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse = objectMapper.readValue(wellknownResponse, CredentialIssuerWellKnownResponse.class);
                        new CredentialIssuerWellknownResponseValidator().validate(credentialIssuerWellKnownResponse, validator);
                        return credentialIssuerWellKnownResponse;
                    } catch (JsonProcessingException | ApiNotAccessibleException | InvalidWellknownResponseException e) {
                        throw new RuntimeException(e);
                    }
                })
                .orElseThrow(ApiNotAccessibleException::new);
    }

    @Override
    public CredentialsSupportedResponse getIssuerWellknownForCredentialType(String issuerId, String credentialId) throws ApiNotAccessibleException, IOException {
        CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse = getIssuerWellknown(issuerId);
        CredentialsSupportedResponse credentialsSupportedResponse = credentialIssuerWellKnownResponse.getCredentialConfigurationsSupported().get(credentialId);
        if(credentialsSupportedResponse == null){
            throw new ApiNotAccessibleException();
        }
        return credentialsSupportedResponse;
    }


}


