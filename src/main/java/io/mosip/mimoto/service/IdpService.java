package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerConfiguration;
import io.mosip.mimoto.exception.IssuerOnboardingException;
import org.springframework.http.HttpEntity;
import org.springframework.util.MultiValueMap;

import java.io.IOException;
import java.util.Map;

public interface IdpService {
    HttpEntity<MultiValueMap<String, String>> constructGetTokenRequest(Map<String, String> params, IssuerDTO issuerDTO, String authorizationAudience) throws IOException, IssuerOnboardingException;

    String getTokenEndpoint(CredentialIssuerConfiguration credentialIssuerConfiguration);
}
