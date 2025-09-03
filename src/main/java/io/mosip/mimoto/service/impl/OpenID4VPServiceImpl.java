package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.dto.VerifiablePresentationResponseDTO;
import io.mosip.mimoto.dto.VerifiablePresentationVerifierDTO;
import io.mosip.mimoto.dto.openid.VerifierDTO;
import io.mosip.mimoto.dto.openid.VerifiersDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.service.OpenID4VPService;
import io.mosip.mimoto.service.VerifierService;
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest;
import io.mosip.openID4VP.authorizationRequest.Verifier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import io.mosip.openID4VP.OpenID4VP;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

@Service
public class OpenID4VPServiceImpl implements OpenID4VPService {

    @Autowired
    private VerifierService verifierService;

    @Override
    public VerifiablePresentationResponseDTO handleVPAuthorizationRequest(String urlEncodedVPAuthorizationRequest, String walletId)
            throws ApiNotAccessibleException, IOException {
        String presentationId = generatePresentationId();
        AuthorizationRequest authorizationRequest = authenticateVerifier(presentationId, urlEncodedVPAuthorizationRequest, getPreRegisteredVerifiers());
        VerifiablePresentationVerifierDTO verifiablePresentationVerifierDTO = createVPResponseVerifierDTO(authorizationRequest, walletId);

        return new VerifiablePresentationResponseDTO(presentationId, verifiablePresentationVerifierDTO);
    }

    private String generatePresentationId() {
        return UUID.randomUUID().toString();
    }

    private List<Verifier> getPreRegisteredVerifiers() throws ApiNotAccessibleException, IOException {
        VerifiersDTO preRegisteredVerifiers = verifierService.getTrustedVerifiers();
        return preRegisteredVerifiers.getVerifiers().stream()
                .map(verifierDTO -> new Verifier(verifierDTO.getClientId(), verifierDTO.getResponseUris()))
                .toList();
    }

    private AuthorizationRequest authenticateVerifier(String presentationId, String urlEncodedVPAuthorizationRequest,
                                                      List<Verifier> trustedVerifiers) {
        OpenID4VP openID4VP = new OpenID4VP(presentationId);
        return openID4VP.authenticateVerifier(urlEncodedVPAuthorizationRequest, trustedVerifiers);
    }

    private VerifiablePresentationVerifierDTO createVPResponseVerifierDTO(AuthorizationRequest authorizationRequest, String walletId) throws ApiNotAccessibleException, IOException {

        boolean isVerifierPreRegisteredWithWallet = verifierService.getTrustedVerifiers().getVerifiers().stream().map(
                VerifierDTO::getClientId).toList().contains(authorizationRequest.getClientId());

        boolean isVerifierTrustedByWallet = verifierService.doesVerifierExistInDB(authorizationRequest.getClientId(), walletId);

        assert authorizationRequest.getClientMetadata() != null;
        return new VerifiablePresentationVerifierDTO(
                authorizationRequest.getClientId(),
                authorizationRequest.getClientMetadata().getClientName(),
                authorizationRequest.getClientMetadata().getLogoUri(),
                isVerifierTrustedByWallet,
                isVerifierPreRegisteredWithWallet,
                authorizationRequest.getRedirectUri()
        );
    }
}
