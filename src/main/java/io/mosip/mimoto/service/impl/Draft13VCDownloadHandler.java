package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.Draft13VCCredentialRequest;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.mimoto.VerifiableCredentialResponse;
import io.mosip.mimoto.exception.CredentialProcessingException;
import io.mosip.mimoto.exception.DPoPChallengeException;
import io.mosip.mimoto.exception.ExternalServiceUnavailableException;
import io.mosip.mimoto.exception.InvalidCredentialResourceException;
import io.mosip.mimoto.constant.DPoPConstants;
import io.mosip.mimoto.service.Draft13CredentialRequestService;
import io.mosip.mimoto.service.VCDownloadHandler;
import io.mosip.mimoto.util.CredentialApiClient;
import io.mosip.mimoto.util.RestApiClient;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import static io.mosip.mimoto.exception.ErrorConstants.CREDENTIAL_DOWNLOAD_EXCEPTION;
import static io.mosip.mimoto.exception.ErrorConstants.SERVER_UNAVAILABLE;

@Slf4j
@Component("draft-13")
public class Draft13VCDownloadHandler implements VCDownloadHandler {
    private final Draft13CredentialRequestService draft13CredentialRequestService;
    private final RestApiClient restApiClient;
    private final CredentialApiClient credentialApiClient;

    public Draft13VCDownloadHandler(Draft13CredentialRequestService draft13CredentialRequestService,
                                    RestApiClient restApiClient, CredentialApiClient credentialApiClient) {
        this.draft13CredentialRequestService = draft13CredentialRequestService;
        this.restApiClient = restApiClient;
        this.credentialApiClient = credentialApiClient;
    }

    @Override
    public VCCredentialResponse downloadCredential(IssuerDTO issuerDTO, String credentialConfigurationId, CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse, TokenResponseDTO tokenResponse, String walletId, String base64Key, boolean isLoginFlow, String dPoPProof) throws CredentialProcessingException, InvalidCredentialResourceException, ExternalServiceUnavailableException {
        Draft13VCCredentialRequest vcCredentialRequest;
        try {
            vcCredentialRequest = draft13CredentialRequestService.buildRequest(issuerDTO, credentialConfigurationId, credentialIssuerWellKnownResponse, tokenResponse.getC_nonce(), walletId, base64Key, isLoginFlow);
        } catch (Exception e) {
            log.error("Failed to generate VC credential request for issuerId: {}", issuerDTO.getIssuer_id(), e);
            throw new CredentialProcessingException(CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(), "Unable to generate credential request", e);
        }

        return fetchCredential(credentialIssuerWellKnownResponse.getCredentialEndPoint(), vcCredentialRequest, tokenResponse, issuerDTO.getIssuer_id(), credentialConfigurationId, dPoPProof);
    }

    private VCCredentialResponse fetchCredential(String credentialEndpoint, Draft13VCCredentialRequest vcCredentialRequest, TokenResponseDTO tokenResponse, String issuerId, String credentialConfigId,
                                                 String dPoPProof) throws InvalidCredentialResourceException, ExternalServiceUnavailableException {
        VerifiableCredentialResponse response;

        try {
            if (isDPoPRequest(tokenResponse, dPoPProof)) {
                response = credentialApiClient.postCredentialApi(credentialEndpoint, MediaType.APPLICATION_JSON,
                        vcCredentialRequest, VerifiableCredentialResponse.class,
                        tokenResponse.getAccess_token(), tokenResponse.getToken_type(), dPoPProof);
            } else {
                response = restApiClient.postApi(credentialEndpoint, MediaType.APPLICATION_JSON,
                        vcCredentialRequest, VerifiableCredentialResponse.class, tokenResponse.getAccess_token());
            }
        } catch (DPoPChallengeException e) {
            throw e;
        } catch (Exception e) {
            String message = String.format("Unable to download credential from issuerId: %s, credentialConfigurationId: %s", issuerId, credentialConfigId);
            throw new ExternalServiceUnavailableException(SERVER_UNAVAILABLE.getErrorCode(), message, e);
        }

        if (response == null) {
            String message = String.format("Unable to download credential from issuerId: %s, credentialConfigurationId: %s", issuerId, credentialConfigId);
            throw new ExternalServiceUnavailableException(SERVER_UNAVAILABLE.getErrorCode(), message);
        }

        if (response.getCredential() == null) {
            throw new InvalidCredentialResourceException("Credential response did not contain a credential");
        }

        log.debug("VC Credential Response received");
        return VCCredentialResponse.builder()
                .format(vcCredentialRequest.getFormat())
                .credential(response.getCredential())
                .build();
    }

    private static boolean isDPoPRequest(TokenResponseDTO tokenResponse, String dPoPProof) {
        if (dPoPProof == null || dPoPProof.isBlank()) {
            return false;
        }
        String tokenType = tokenResponse.getToken_type();
        return tokenType == null || !DPoPConstants.BEARER_TOKEN_TYPE.equalsIgnoreCase(tokenType);
    }
}