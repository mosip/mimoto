package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.resident.WalletCredentialResponseDTO;

public interface WalletCredentialViewService {
    WalletCredentialResponseDTO fetchVerifiableCredential(String credentialId, String base64EncodedWalletKey, String locale) throws Exception;
}
