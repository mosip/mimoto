package io.mosip.mimoto.service.impl;


import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.dto.mimoto.AuthorizationServerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerConfigurationResponse;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.AuthorizationServerWellknownResponseException;
import io.mosip.mimoto.exception.InvalidIssuerIdException;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import io.mosip.mimoto.service.AuthorizationServerService;
import io.mosip.mimoto.service.IssuerWellknownService;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.util.Utilities;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.stream.Collectors;


@Service
@Slf4j
public class IssuersServiceImpl implements IssuersService {

    @Autowired
    private Utilities utilities;

    @Autowired
    private AuthorizationServerService authorizationServerService;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private IssuerWellknownService issuerWellknownService;

    @Override
    public IssuersDTO getIssuers(String search) throws ApiNotAccessibleException, AuthorizationServerWellknownResponseException, IOException, InvalidWellknownResponseException {
        IssuersDTO issuersDTO = getAllIssuers();
        issuersDTO = getAllEnabledIssuers(issuersDTO);
        issuersDTO = getFilteredIssuers(issuersDTO, search);

        return issuersDTO;
    }

    @Override
    public IssuerDTO getIssuerDetails(String issuerId) throws ApiNotAccessibleException, IOException, AuthorizationServerWellknownResponseException, InvalidWellknownResponseException {
        IssuersDTO issuersDTO = getAllIssuers();
        issuersDTO = getAllEnabledIssuers(issuersDTO);

        return issuersDTO.getIssuers().stream()
                .filter(issuer -> issuer.getIssuer_id().equals(issuerId))
                .findFirst()
                .orElseThrow(InvalidIssuerIdException::new);
    }

    private IssuersDTO getAllEnabledIssuers(IssuersDTO issuersDTO) {
        return new IssuersDTO(issuersDTO.getIssuers().stream()
                .filter(issuer -> "true".equals(issuer.getEnabled()))
                .collect(Collectors.toList()));
    }

    private IssuersDTO getFilteredIssuers(IssuersDTO issuersDTO, String search) {
        if (StringUtils.isEmpty(search)) {
            return issuersDTO;
        }

        return new IssuersDTO(issuersDTO.getIssuers().stream()
                .filter(issuer -> issuer.getDisplay().stream()
                        .anyMatch(displayDTO -> displayDTO.getTitle().toLowerCase().contains(search.toLowerCase())))
                .collect(Collectors.toList()));
    }

    @Override
    public IssuersDTO getAllIssuers() throws ApiNotAccessibleException, AuthorizationServerWellknownResponseException, IOException, InvalidWellknownResponseException {

        IssuersDTO issuersDTO;
        String issuersConfigJsonValue = utilities.getIssuersConfigJsonValue();
        if (issuersConfigJsonValue == null) {
            throw new ApiNotAccessibleException();
        }

        try {
            issuersDTO = objectMapper.readValue(issuersConfigJsonValue, IssuersDTO.class);
        } catch (Exception e) {
            throw e;
        }
        for (IssuerDTO issuerDTO : issuersDTO.getIssuers()) {
            updateIssuerWithAuthServerConfig(issuerDTO);
        }

        return issuersDTO;
    }

    @Override
    @Cacheable(value = "credentialIssuerConfig", key = "{#issuerId}")
    public CredentialIssuerConfigurationResponse getIssuerConfiguration(String issuerId) throws ApiNotAccessibleException, IOException, AuthorizationServerWellknownResponseException, InvalidWellknownResponseException {
        CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse = issuerWellknownService.getWellknown(getIssuerDetails(issuerId).getCredential_issuer_host());
        AuthorizationServerWellKnownResponse authorizationServerWellKnownResponse = authorizationServerService.getWellknown(credentialIssuerWellKnownResponse.getAuthorizationServers().get(0));

        return new CredentialIssuerConfigurationResponse(
                credentialIssuerWellKnownResponse.getCredentialIssuer(),
                credentialIssuerWellKnownResponse.getAuthorizationServers(),
                credentialIssuerWellKnownResponse.getCredentialEndPoint(),
                credentialIssuerWellKnownResponse.getCredentialConfigurationsSupported(),
                authorizationServerWellKnownResponse
        );
    }

    private void updateIssuerWithAuthServerConfig(IssuerDTO issuerDTO) throws AuthorizationServerWellknownResponseException, ApiNotAccessibleException, IOException, InvalidWellknownResponseException {
        CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse = issuerWellknownService.getWellknown(issuerDTO.getCredential_issuer_host());
        AuthorizationServerWellKnownResponse authorizationServerWellKnownResponse = authorizationServerService.getWellknown(credentialIssuerWellKnownResponse.getAuthorizationServers().get(0));
        String tokenEndpoint = authorizationServerWellKnownResponse.getTokenEndpoint();
        issuerDTO.setAuthorization_audience(tokenEndpoint);
        issuerDTO.setProxy_token_endpoint(tokenEndpoint);
    }
}