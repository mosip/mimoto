package io.mosip.mimoto.service.impl;


import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.util.IssuerConfigUtil;
import io.mosip.mimoto.util.Utilities;
import jakarta.validation.constraints.NotBlank;
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
    private ObjectMapper objectMapper;

    @Autowired
    private IssuerConfigUtil issuersConfigUtil;

    @Override
    @Cacheable(value = "issuersConfig", key = "#p0 ?: 'allIssuersConfig'")
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
    public IssuersDTO getAllIssuers() throws ApiNotAccessibleException, IOException {
        IssuersDTO issuersDTO;
        String issuersConfigJsonValue = utilities.getIssuersConfigJsonValue();
        if (issuersConfigJsonValue == null) {
            throw new ApiNotAccessibleException();
        }

        issuersDTO = objectMapper.readValue(issuersConfigJsonValue, IssuersDTO.class);

        return issuersDTO;
    }

    @Override
    public CredentialIssuerConfiguration getIssuerConfiguration(String issuerId) throws ApiNotAccessibleException, IOException, AuthorizationServerWellknownResponseException, InvalidWellknownResponseException {
        CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse = issuersConfigUtil.getIssuerWellknown(getIssuerDetails(issuerId).getCredential_issuer_host());
        AuthorizationServerWellKnownResponse authorizationServerWellKnownResponse = issuersConfigUtil.getAuthServerWellknown(credentialIssuerWellKnownResponse.getAuthorizationServers().get(0));

        return new CredentialIssuerConfiguration(
                credentialIssuerWellKnownResponse.getCredentialIssuer(),
                credentialIssuerWellKnownResponse.getAuthorizationServers(),
                credentialIssuerWellKnownResponse.getCredentialEndPoint(),
                credentialIssuerWellKnownResponse.getCredentialConfigurationsSupported(),
                authorizationServerWellKnownResponse
        );
    }

    public IssuerConfig getIssuerConfig(String issuerId, @NotBlank String credentialType) throws ApiNotAccessibleException, IOException, InvalidIssuerIdException, AuthorizationServerWellknownResponseException, InvalidWellknownResponseException {
        log.info("Fetching issuer config for issuerId: {}", issuerId);
        try {
            IssuerDTO issuerDTO = getIssuerDetails(issuerId);
            CredentialIssuerWellKnownResponse wellKnownResponse = issuersConfigUtil.getIssuerWellknown(issuerDTO.getCredential_issuer_host());
            return new IssuerConfig(
                    issuerDTO,
                    wellKnownResponse,
                    wellKnownResponse.getCredentialConfigurationsSupported().get(credentialType)
            );
        } catch (Exception e) {
            log.error("Failed to fetch issuer config for issuerId: {}", issuerId, e);
            if (e instanceof InvalidIssuerIdException) {
                throw (InvalidIssuerIdException) e;
            }
            throw new ApiNotAccessibleException("Unable to fetch issuer configuration for issuerId: " + issuerId, e);
        }
    }
}