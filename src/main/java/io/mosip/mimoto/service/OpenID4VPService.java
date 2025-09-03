package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.VerifiablePresentationResponseDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;

import java.io.IOException;

public interface OpenID4VPService {
    VerifiablePresentationResponseDTO handleVPAuthorizationRequest(String urlEncodedVPAuthorizationRequest, String walletId) throws ApiNotAccessibleException, IOException;
}

