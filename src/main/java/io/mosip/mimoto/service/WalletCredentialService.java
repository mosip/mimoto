package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.VerifiableCredentialResponseDTO;
import io.mosip.mimoto.model.SigningAlgorithm;

import java.util.List;

public interface WalletCredentialService {
    VerifiableCredentialResponseDTO fetchAndStoreCredential(String issuerId, String credentialType, TokenResponseDTO response, String credentialValidity, String locale, String walletId, String base64EncodedWalletKey, SigningAlgorithm algorithm) throws Exception;

    List<VerifiableCredentialResponseDTO> fetchAllCredentialsForWallet(String walletId, String walletKey, String locale);
}
