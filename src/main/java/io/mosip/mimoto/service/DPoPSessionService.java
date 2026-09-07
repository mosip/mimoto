package io.mosip.mimoto.service;

import io.mosip.mimoto.constant.DPoPConstants;
import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.dpop.DPoPSession;
import io.mosip.mimoto.dto.dpop.IssuerAuthorizeRequest;
import io.mosip.mimoto.dto.dpop.IssuerAuthorizeResponse;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerConfiguration;
import io.mosip.mimoto.dto.pkce.PkceSession;
import io.mosip.mimoto.util.AuthorizationUrlBuilder;
import io.mosip.mimoto.exception.DPoPChallengeException;
import io.mosip.mimoto.exception.InvalidRequestException;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

import static io.mosip.mimoto.exception.ErrorConstants.INVALID_REQUEST;

@Service
@Slf4j
public class DPoPSessionService {

    private final IssuersService issuersService;
    private final DPoPManager dPoPManager;
    private final PkceSessionManager pkceSessionManager;

    public DPoPSessionService(IssuersService issuersService, DPoPManager dPoPManager,
                              PkceSessionManager pkceSessionManager) {
        this.issuersService = issuersService;
        this.dPoPManager = dPoPManager;
        this.pkceSessionManager = pkceSessionManager;
    }

    public IssuerAuthorizeResponse createAuthorizationUrl(HttpSession httpSession, String issuerId,
                                                          IssuerAuthorizeRequest request)
            throws Exception {
        if (request == null) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "authorization request is required");
        }
        CredentialIssuerConfiguration configuration = issuersService.getIssuerConfiguration(issuerId);
        IssuerDTO issuer = issuersService.getIssuerDetails(issuerId);
        if (configuration.getAuthorizationServerWellKnownResponse() == null
                || StringUtils.isBlank(configuration.getAuthorizationServerWellKnownResponse().getAuthorizationEndpoint())) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "authorization_endpoint is missing");
        }
        if (StringUtils.isBlank(issuer.getClient_id())) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "client_id is missing");
        }
        PkceSession pkceSession = pkceSessionManager.createSession(request.getRedirectUri());
        DPoPSession dPoPSession = createDPoPSession(
                httpSession, issuerId, pkceSession.getState(), configuration);
        pkceSessionManager.store(httpSession, pkceSession);
        String authorizationUrl = AuthorizationUrlBuilder.build(
                configuration.getAuthorizationServerWellKnownResponse().getAuthorizationEndpoint(),
                issuer.getClient_id(),
                pkceSession.getRedirectUri(),
                request.getScope(),
                request.getResponseType(),
                pkceSession.getState(),
                pkceSession.getCodeChallenge(),
                "S256",
                request.getUiLocales(),
                dPoPManager.jwkThumbprint(dPoPSession));
        return IssuerAuthorizeResponse.builder()
                .authorizationUrl(authorizationUrl)
                .state(pkceSession.getState())
                .build();
    }

    private DPoPSession createDPoPSession(HttpSession httpSession, String issuerId, String state,
                                          CredentialIssuerConfiguration configuration) {
        if (httpSession == null) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "HTTP session is required for DPoP");
        }
        String alg = dPoPManager.selectAlgorithm(
                configuration.getAuthorizationServerWellKnownResponse().getDPoPSigningAlgValuesSupported());
        DPoPSession dPoPSession = dPoPManager.createSession(
                state,
                alg,
                configuration.getAuthorizationServerWellKnownResponse().getTokenEndpoint());
        dPoPSession.setIssuerId(issuerId);
        store(httpSession, dPoPSession);
        log.info("Created DPoP session alg {}", alg);
        return dPoPSession;
    }

    public DPoPSession require(HttpSession httpSession, String state) {
        DPoPSession session = find(httpSession, state);
        if (session == null) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "DPoP session not found");
        }
        return session;
    }

    public DPoPSession find(HttpSession httpSession, String state) {
        if (httpSession == null || StringUtils.isBlank(state)) {
            return null;
        }
        Map<String, DPoPSession> sessions = sessions(httpSession);
        return sessions.get(state);
    }

    public void store(HttpSession httpSession, DPoPSession dPoPSession) {
        synchronized (httpSession) {
            Map<String, DPoPSession> sessions = sessions(httpSession);
            sessions.put(dPoPSession.getState(), dPoPSession);
            httpSession.setAttribute(SessionKeys.DPOP_SESSION, sessions);
        }
    }

    public void remove(HttpSession httpSession, String state) {
        if (httpSession == null || StringUtils.isBlank(state)) {
            return;
        }
        synchronized (httpSession) {
            Map<String, DPoPSession> sessions = sessions(httpSession);
            sessions.remove(state);
            httpSession.setAttribute(SessionKeys.DPOP_SESSION, sessions);
        }
        pkceSessionManager.remove(httpSession, state);
    }

    public Map<String, String> authorizationCodeParams(HttpSession httpSession, String state, String code, String issuerId) {
        DPoPSession dPoPSession = require(httpSession, state);
        requireMatchingIssuer(dPoPSession, issuerId);
        PkceSession pkceSession = pkceSessionManager.require(httpSession, state);
        if (StringUtils.isBlank(pkceSession.getCodeVerifier()) || StringUtils.isBlank(pkceSession.getRedirectUri())) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "PKCE session is incomplete");
        }
        if (StringUtils.isBlank(code)) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "code cannot be blank");
        }
        Map<String, String> params = new HashMap<>();
        params.put("code", code);
        params.put("code_verifier", pkceSession.getCodeVerifier());
        params.put("redirect_uri", pkceSession.getRedirectUri());
        params.put("grant_type", "authorization_code");
        params.put("issuer", dPoPSession.getIssuerId());
        params.put("state", state);
        return params;
    }

    public String credentialProof(HttpSession httpSession, String state, String issuerId, TokenResponseDTO token) {
        DPoPSession session = find(httpSession, state);
        if (session == null || token == null || StringUtils.isBlank(token.getAccess_token())) {
            return null;
        }
        requireMatchingIssuer(session, issuerId);
        if (StringUtils.isNotBlank(token.getToken_type())
                && !DPoPConstants.DPOP_TOKEN_TYPE.equalsIgnoreCase(token.getToken_type())) {
            return null;
        }
        return dPoPManager.generateCredentialProof(
                session, credentialHtu(session.getIssuerId()), token.getAccess_token());
    }

    public String retryCredentialProof(HttpSession httpSession, String state, String issuerId,
                                       TokenResponseDTO token, DPoPChallengeException challenge) {
        String nonce = challenge.getResponseHeaders() != null
                ? challenge.getResponseHeaders().getFirst(DPoPConstants.DPOP_NONCE_HEADER)
                : null;
        DPoPSession session = require(httpSession, state);
        requireMatchingIssuer(session, issuerId);
        String proof = dPoPManager.generateCredentialProof(
                session, credentialHtu(session.getIssuerId()), token.getAccess_token(), nonce);
        store(httpSession, session);
        return proof;
    }

    private void requireMatchingIssuer(DPoPSession session, String issuerId) {
        if (StringUtils.isBlank(session.getIssuerId()) || !session.getIssuerId().equals(issuerId)) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(),
                    "issuer does not match DPoP session");
        }
    }

    private String credentialHtu(String issuerId) {
        try {
            return DPoPManager.normalizeHtu(issuersService.getIssuerConfiguration(issuerId).getCredentialEndPoint());
        } catch (Exception e) {
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Unable to resolve credential endpoint");
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, DPoPSession> sessions(HttpSession httpSession) {
        Map<String, DPoPSession> sessions =
                (Map<String, DPoPSession>) httpSession.getAttribute(SessionKeys.DPOP_SESSION);
        if (sessions == null) {
            return new HashMap<>();
        }
        return new HashMap<>(sessions);
    }
}
