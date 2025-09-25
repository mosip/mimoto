package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.service.VerifierService;
import io.mosip.mimoto.util.WalletPresentationUtil;
import io.mosip.openID4VP.OpenID4VP;
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest;
import io.mosip.openID4VP.authorizationRequest.VPFormatSupported;
import io.mosip.openID4VP.authorizationRequest.Verifier;
import io.mosip.openID4VP.authorizationRequest.WalletMetadata;
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinition;
import io.mosip.openID4VP.constants.VPFormatType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.List;
import java.util.Map;

@Component
@Slf4j
public class OpenID4VPService {

    @Autowired
    private VerifierService verifierService;

    public OpenID4VP create(String presentationId) {
        WalletMetadata walletMetadata = new WalletMetadata();
        walletMetadata.setVpFormatsSupported(Map.of(VPFormatType.LDP_VC, new VPFormatSupported(List.of("EEd25519Signature2020"))));

        return new OpenID4VP(
                presentationId,
                walletMetadata
        );
    }

    /**
     * Extracts the presentation definition from the VerifiablePresentationSessionData object.
     *
     * @return The presentation definition if found, null otherwise.
     */
    public PresentationDefinition resolvePresentationDefinition(String pesentationId, String authorationRequest, boolean isVerifierClientPreregistered) throws ApiNotAccessibleException, IOException {
        if (pesentationId == null || authorationRequest == null) {
            log.warn("Session data or OpenID4VP is null");
            return null;
        }
        OpenID4VP openID4VP = create(pesentationId);
        List<Verifier> preRegisteredVerifiers = verifierService.getTrustedVerifiers().getVerifiers().stream()
                .map(WalletPresentationUtil::mapToVerifier)
                .toList();

        AuthorizationRequest authorizationRequest = openID4VP.authenticateVerifier(authorationRequest, preRegisteredVerifiers, isVerifierClientPreregistered);
        return authorizationRequest.getPresentationDefinition();
    }
}