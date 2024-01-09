package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.service.IdpService;
import io.mosip.mimoto.util.JoseUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Map;

@Service
public class IdpSunbirdServiceImpl implements IdpService {

    @Value("${mosip.oidc.sunbird.client.id}")
    public String clientId;

    @Value("${mosip.oidc.client.assertion.type}")
    String clientAssertionType;

    @Value("${mosip.oidc.p12.filename}")
    private String fileName;

    @Value("${mosip.oidc.p12.password}")
    private String cyptoPassword;

    @Value("${mosip.oidc.p12.path}")
    String keyStorePath;

    @Value("${mosip.oidc.sunbird.p12.alias}")
    private String alias;

    @Value("${mosip.oidc.sunbird.esignet.aud}")
    private String audience;

    @Value("${mosip.oidc.sunbird.esignet.token.endpoint}")
    String tokenEndpoint;

    @Autowired
    JoseUtil joseUtil;

    @Override
    public HttpEntity<MultiValueMap<String, String>> constructGetTokenRequest(Map<String, String> params) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        String clientAssertion = joseUtil.getJWT(clientId, keyStorePath, fileName, alias, cyptoPassword, audience);

        MultiValueMap<String, String> map= new LinkedMultiValueMap<>();
        map.add("code", params.get("code"));
        map.add("client_id", clientId);
        map.add("grant_type", params.get("grant_type"));
        map.add("redirect_uri", params.get("redirect_uri"));
        map.add("client_assertion", clientAssertion.replace("[","").replace("]",""));
        map.add("client_assertion_type", clientAssertionType);
        map.add("code_verifier", params.get("code_verifier"));

        return new HttpEntity<>(map, headers);
    }
    @Override
    public String getTokenEndpoint(){
        return tokenEndpoint;
    }


}
