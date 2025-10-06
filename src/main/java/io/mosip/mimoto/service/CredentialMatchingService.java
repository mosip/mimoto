package io.mosip.mimoto.service;


import io.mosip.mimoto.dto.MatchingCredentialsWithWalletDataDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.ApiNotAccessibleException;

import java.io.IOException;

public interface CredentialMatchingService {
    MatchingCredentialsWithWalletDataDTO getMatchingCredentials(VerifiablePresentationSessionData sessionData, String walletId, String base64Key) throws ApiNotAccessibleException, IOException;
}