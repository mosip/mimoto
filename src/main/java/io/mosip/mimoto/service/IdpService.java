package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.IssuerDTO;
import org.springframework.http.HttpEntity;
import org.springframework.util.MultiValueMap;

import java.util.Map;

public interface IdpService {
    HttpEntity<MultiValueMap<String, String>> constructGetTokenRequest(Map<String, String> params, IssuerDTO issuerDTO);

    String getTokenEndpoint(IssuerDTO issuerDTO);
}
