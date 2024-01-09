package io.mosip.mimoto.service;

import org.springframework.http.HttpEntity;
import org.springframework.util.MultiValueMap;

import java.util.Map;

public interface IdpService {
    HttpEntity<MultiValueMap<String, String>> constructGetTokenRequest(Map<String, String> params);

    String getTokenEndpoint();
}
