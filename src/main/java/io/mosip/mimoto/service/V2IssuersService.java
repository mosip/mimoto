package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.dto.v2.IssuerSupportedCredentialsResponse;
import io.mosip.mimoto.exception.ApiNotAccessibleException;

import java.io.ByteArrayInputStream;
import java.io.IOException;

public interface V2IssuersService {
    IssuersDTO getAllIssuers(String search) throws ApiNotAccessibleException, IOException;


    IssuerSupportedCredentialsResponse getCredentialsSupported(String issuerId, String search) throws ApiNotAccessibleException, IOException;

    ByteArrayInputStream generatePdfForVerifiableCredentials(String token, String issuerId, String credentialsSupportedId) throws Exception;
}
