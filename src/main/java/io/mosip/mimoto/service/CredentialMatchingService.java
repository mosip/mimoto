package io.mosip.mimoto.service;


import io.mosip.mimoto.dto.MatchingCredentialsWithWalletDataDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationDefinitionDTO;

public interface CredentialMatchingService {
    MatchingCredentialsWithWalletDataDTO getMatchingCredentials(PresentationDefinitionDTO presentationDefinition, String walletId, String base64Key);
}
