package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.MatchingCredentialsResponseDTO;
import io.mosip.mimoto.dto.VerifiablePresentationResponseDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationDefinitionDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationRequestDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions;

import java.io.IOException;
import java.net.URISyntaxException;

public interface PresentationService {

    String authorizePresentation(PresentationRequestDTO presentationRequestDTO) throws ApiNotAccessibleException, IOException;
    VerifiablePresentationResponseDTO handleVPAuthorizationRequest(String urlEncodedVPAuthorizationRequest, String walletId) throws ApiNotAccessibleException, IOException, OpenID4VPExceptions, URISyntaxException;
    MatchingCredentialsResponseDTO getMatchingCredentials(PresentationDefinitionDTO presentationDefinition, String walletId, String base64Key) throws ApiNotAccessibleException, IOException;
}
