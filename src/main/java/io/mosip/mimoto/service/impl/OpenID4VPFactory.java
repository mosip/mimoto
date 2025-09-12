package io.mosip.mimoto.service.impl;

import io.mosip.openID4VP.OpenID4VP;
import io.mosip.openID4VP.authorizationRequest.VPFormatSupported;
import io.mosip.openID4VP.authorizationRequest.WalletMetadata;
import io.mosip.openID4VP.constants.VPFormatType;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

@Component
public class OpenID4VPFactory {
    public OpenID4VP create(String presentationId) {
        WalletMetadata walletMetadata = new WalletMetadata();
        walletMetadata.setVpFormatsSupported(Map.of(VPFormatType.LDP_VC, new VPFormatSupported(List.of("EEd25519Signature2020"))));

        return new OpenID4VP(
                presentationId,
                walletMetadata
        );
    }
}