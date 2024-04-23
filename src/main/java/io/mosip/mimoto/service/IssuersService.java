package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.dto.mimoto.CredentialsSupportedResponse;
import io.mosip.mimoto.dto.mimoto.IssuerSupportedCredentialsResponse;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.InvalidIssuerIdException;

import java.io.ByteArrayInputStream;
import java.io.IOException;

public interface IssuersService {
    IssuersDTO getAllIssuers(String search) throws ApiNotAccessibleException, IOException;

    IssuersDTO getAllIssuersWithAllFields() throws ApiNotAccessibleException, IOException;

    IssuerDTO getIssuerConfig(String issuerId) throws ApiNotAccessibleException, IOException, InvalidIssuerIdException;

    IssuerSupportedCredentialsResponse getCredentialsSupported(String issuerId, String search) throws ApiNotAccessibleException, IOException;

    ByteArrayInputStream generatePdfForVerifiableCredentials(String accessToken, IssuerDTO issuerDTO, CredentialsSupportedResponse credentialsSupportedResponse, String credentialEndPoint) throws Exception;



}
