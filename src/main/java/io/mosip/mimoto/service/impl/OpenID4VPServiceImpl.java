package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.dto.VerifiablePresentationResponseDTO;
import io.mosip.mimoto.dto.VerifiablePresentationVerifierDTO;
import io.mosip.mimoto.dto.openid.VerifierDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.service.OpenID4VPService;
import io.mosip.mimoto.service.VerifierService;
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest;
import io.mosip.openID4VP.authorizationRequest.Verifier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import io.mosip.openID4VP.OpenID4VP;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
public class OpenID4VPServiceImpl implements OpenID4VPService {

    @Autowired
    private VerifierService verifierService;

    private OpenID4VP openID4VP;

    @Override
    public VerifiablePresentationResponseDTO handleVPAuthorizationRequest(String urlEncodedVPAuthorizationRequest, String walletId)
            throws ApiNotAccessibleException, IOException {
        String presentationId = UUID.randomUUID().toString();

        //Initialize OpenID4VP instance with presentationId as traceability id for each new Verifiable Presentation request
        this.openID4VP = new OpenID4VP(presentationId);

        AuthorizationRequest authorizationRequest = openID4VP.authenticateVerifier(urlEncodedVPAuthorizationRequest, getPreRegisteredVerifiers());
        VerifiablePresentationVerifierDTO verifiablePresentationVerifierDTO = createVPResponseVerifierDTO(authorizationRequest, walletId);
        VerifiablePresentationSessionData verifiablePresentationSessionData = new VerifiablePresentationSessionData(authorizationRequest, Instant.now());

        return new VerifiablePresentationResponseDTO(presentationId, verifiablePresentationVerifierDTO, verifiablePresentationSessionData);
    }

    private List<Verifier> getPreRegisteredVerifiers() throws ApiNotAccessibleException, IOException {

        return verifierService.getTrustedVerifiers().getVerifiers().stream()
                .map(verifierDTO -> new Verifier(verifierDTO.getClientId(), verifierDTO.getResponseUris()))
                .toList();
    }

    private VerifiablePresentationVerifierDTO createVPResponseVerifierDTO(AuthorizationRequest authorizationRequest, String walletId) throws ApiNotAccessibleException, IOException {

        boolean isVerifierPreRegisteredWithWallet = verifierService.getTrustedVerifiers().getVerifiers().stream().map(
                VerifierDTO::getClientId).toList().contains(authorizationRequest.getClientId());

        boolean isVerifierTrustedByWallet = verifierService.doesVerifierExistInDB(authorizationRequest.getClientId(), walletId);

        return new VerifiablePresentationVerifierDTO(
                authorizationRequest.getClientId(),
                authorizationRequest.getClientMetadata() != null && authorizationRequest.getClientMetadata().getClientName() != null
                        ? authorizationRequest.getClientMetadata().getClientName()
                        : authorizationRequest.getClientId(),
                authorizationRequest.getClientMetadata() != null ? authorizationRequest.getClientMetadata().getLogoUri() : null,
                isVerifierTrustedByWallet,
                isVerifierPreRegisteredWithWallet,
                authorizationRequest.getRedirectUri()
        );
    }
}
