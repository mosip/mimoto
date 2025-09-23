package io.mosip.mimoto.service;


import io.mosip.mimoto.dto.MatchingCredentialsWithWalletDataDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;

public interface CredentialMatchingService {
    MatchingCredentialsWithWalletDataDTO getMatchingCredentials(VerifiablePresentationSessionData sessionData, String walletId, String base64Key);
}
