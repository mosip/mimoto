package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.VCCredentialRequest;

public interface CredentialRequestService {
    VCCredentialRequest buildRequest(
            IssuerDTO issuerDTO,
            String credentialType,
            CredentialIssuerWellKnownResponse wellKnownResponse,
            String cNonce,
            String walletId,
            String base64EncodedWalletKey,
            boolean isLoginFlow
    ) throws Exception;
}