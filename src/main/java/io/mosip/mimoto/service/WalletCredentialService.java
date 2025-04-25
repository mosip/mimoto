package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.VerifiableCredentialResponseDTO;
import io.mosip.mimoto.dto.resident.WalletCredentialResponseDTO;
import io.mosip.mimoto.exception.CorruptedEncryptedDataException;
import io.mosip.mimoto.exception.DecryptionException;
import io.mosip.mimoto.exception.ExternalServiceUnavailableException;
import io.mosip.mimoto.exception.InvalidCredentialResourceException;

import java.util.List;

public interface WalletCredentialService {
    VerifiableCredentialResponseDTO fetchAndStoreCredential(String issuerId, String credentialType, TokenResponseDTO response, String credentialValidity, String locale, String walletId, String base64EncodedWalletKey) throws ExternalServiceUnavailableException;

    List<VerifiableCredentialResponseDTO> fetchAllCredentialsForWallet(String walletId, String walletKey, String locale);

    WalletCredentialResponseDTO fetchVerifiableCredential(String walletId, String credentialId, String base64EncodedWalletKey, String locale) throws DecryptionException, CorruptedEncryptedDataException, ExternalServiceUnavailableException;
}
