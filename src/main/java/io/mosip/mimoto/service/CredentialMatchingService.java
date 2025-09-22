package io.mosip.mimoto.service;

import java.io.IOException;

import io.mosip.mimoto.dto.MatchingCredentialsWithWalletDataDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationDefinitionDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;

public interface CredentialMatchingService {
    MatchingCredentialsWithWalletDataDTO getMatchingCredentials(PresentationDefinitionDTO presentationDefinition, String walletId, String base64Key) throws ApiNotAccessibleException, IOException;
}
