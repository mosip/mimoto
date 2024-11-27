package io.mosip.mimoto.service;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Map;

public interface CredentialService {
    TokenResponseDTO getTokenResponse(Map<String, String> params, String issuerId) throws ApiNotAccessibleException, IOException;

    ByteArrayInputStream downloadCredentialAsPDF(String issuerId, String credentialType, TokenResponseDTO response, String credentialValidity) throws Exception;
}
