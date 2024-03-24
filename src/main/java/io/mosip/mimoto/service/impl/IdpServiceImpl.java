package io.mosip.mimoto.service.impl;

import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.exception.IssuerOnboardingException;
import io.mosip.mimoto.service.IdpService;
import io.mosip.mimoto.util.JoseUtil;
import io.mosip.mimoto.util.LoggerUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.io.IOException;
import java.util.Map;

@Service
public class IdpServiceImpl implements IdpService {

    @Value("${mosip.oidc.client.assertion.type}")
    String clientAssertionType;

    @Value("${mosip.oidc.p12.filename}")
    private String fileName;

    @Value("${mosip.oidc.p12.password}")
    private String cyptoPassword;

    @Value("${mosip.oidc.p12.path}")
    String keyStorePath;

    @Autowired
    JoseUtil joseUtil;

    private final Logger logger = LoggerUtil.getLogger(IdpServiceImpl.class);

    @Override
    public HttpEntity<MultiValueMap<String, String>> constructGetTokenRequest(Map<String, String> params, IssuerDTO issuerDTO) throws IOException, IssuerOnboardingException {
        HttpHeaders headers = new HttpHeaders();
        MultiValueMap<String, String> map= new LinkedMultiValueMap<>();

        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        String clientAssertion = joseUtil.getJWT(issuerDTO.getClient_id(), keyStorePath, fileName, issuerDTO.getClient_alias(), cyptoPassword, issuerDTO.getAuthorization_audience());

        map.add("code", params.get("code"));
        map.add("client_id", issuerDTO.getClient_id());
        map.add("grant_type", params.get("grant_type"));
        map.add("redirect_uri", params.get("redirect_uri"));
        map.add("client_assertion", clientAssertion.replace("[","").replace("]",""));
        map.add("client_assertion_type", clientAssertionType);
        map.add("code_verifier", params.get("code_verifier"));

        return new HttpEntity<>(map, headers);
    }

    @Override
    public String getTokenEndpoint(IssuerDTO issuerDTO){
        return issuerDTO.getProxy_token_endpoint();
    }
}
