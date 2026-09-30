package io.mosip.mimoto.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.DPoPConstants;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.mimoto.PushedAuthorizationResponse;
import io.mosip.mimoto.exception.PushedAuthorizationRequestException;
import io.mosip.mimoto.util.JoseUtil;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;

import java.util.List;

@Service
public class PushedAuthorizationRequestService {

    private final JoseUtil joseUtil;
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;
    private final String clientAssertionType;
    private final String fileName;
    private final String cryptoPassword;
    private final String keyStorePath;

    public PushedAuthorizationRequestService(
            JoseUtil joseUtil,
            @Qualifier("restTemplate") RestTemplate restTemplate,
            ObjectMapper objectMapper,
            @Value("${mosip.oidc.client.assertion.type}") String clientAssertionType,
            @Value("${mosip.oidc.p12.filename}") String fileName,
            @Value("${mosip.oidc.p12.password}") String cryptoPassword,
            @Value("${mosip.oidc.p12.path}") String keyStorePath) {
        this.joseUtil = joseUtil;
        this.restTemplate = restTemplate;
        this.objectMapper = objectMapper;
        this.clientAssertionType = clientAssertionType;
        this.fileName = fileName;
        this.cryptoPassword = cryptoPassword;
        this.keyStorePath = keyStorePath;
    }

    public PushedAuthorizationResponse pushAuthorizationRequest(String parEndpoint,
                                             IssuerDTO issuer,
                                             String redirectUri,
                                             String scope,
                                             String state,
                                             String codeChallenge,
                                             String codeChallengeMethod,
                                             String uiLocales,
                                             String dpopJkt) {
        try {
            String clientAssertion = joseUtil.getJWT(
                    issuer.getClient_id(), keyStorePath, fileName,
                    issuer.getClient_alias(), cryptoPassword, parEndpoint);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
            headers.setAccept(List.of(MediaType.APPLICATION_JSON));

            MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
            body.add("response_type", DPoPConstants.AUTHORIZATION_RESPONSE_TYPE);
            body.add("client_id", issuer.getClient_id());
            body.add("redirect_uri", redirectUri);
            body.add("scope", scope);
            body.add("state", state);
            body.add("code_challenge", codeChallenge);
            body.add("code_challenge_method", codeChallengeMethod);
            body.add("client_assertion", clientAssertion.replace("[", "").replace("]", ""));
            body.add("client_assertion_type", clientAssertionType);
            if (StringUtils.isNotBlank(uiLocales)) {
                body.add("ui_locales", uiLocales);
            }
            if (StringUtils.isNotBlank(dpopJkt)) {
                body.add("dpop_jkt", dpopJkt);
            }

            String responseBody = restTemplate.postForObject(
                    parEndpoint, new HttpEntity<>(body, headers), String.class);
            PushedAuthorizationResponse parsed = objectMapper.readValue(responseBody, PushedAuthorizationResponse.class);
            if (parsed == null || StringUtils.isBlank(parsed.getRequestUri())) {
                throw new PushedAuthorizationRequestException(
                        "PAR response from " + parEndpoint + " did not contain a request_uri");
            }
            return parsed;
        } catch (PushedAuthorizationRequestException exception) {
            throw exception;
        } catch (HttpStatusCodeException exception) {
            throw new PushedAuthorizationRequestException(
                    "PAR request failed at " + parEndpoint + " with status " + exception.getStatusCode().value());
        } catch (Exception exception) {
            throw new PushedAuthorizationRequestException(
                    "PAR request failed at " + parEndpoint + ": " + exception.getMessage(), exception);
        }
    }
}
