package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.VerifiablePresentationResponseDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationRequestDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.VPErrorNotSentException;
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions;

import java.io.IOException;
import java.net.URISyntaxException;

public interface PresentationService {

    String authorizePresentation(PresentationRequestDTO presentationRequestDTO) throws ApiNotAccessibleException, IOException;
    VerifiablePresentationResponseDTO handleVPAuthorizationRequest(String urlEncodedVPAuthorizationRequest, String walletId) throws ApiNotAccessibleException, IOException, OpenID4VPExceptions, URISyntaxException;
    void rejectVerifier(String walletId, VerifiablePresentationSessionData vpSessionData, ErrorDTO payload) throws VPErrorNotSentException;
}
