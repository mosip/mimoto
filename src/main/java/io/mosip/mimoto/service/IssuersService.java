package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.InvalidIssuerIdException;
import org.apache.http.auth.InvalidCredentialsException;

import java.io.ByteArrayInputStream;
import java.io.IOException;

public interface IssuersService {
    IssuersDTO getAllIssuers(String search) throws ApiNotAccessibleException, IOException;

    IssuersDTO getAllIssuersWithAllFields() throws ApiNotAccessibleException, IOException;

    IssuerDTO getIssuerConfig(String issuerId) throws ApiNotAccessibleException, IOException, InvalidIssuerIdException;

    IssuerSupportedCredentialsResponse getCredentialsSupported(String issuerId, String search) throws ApiNotAccessibleException, IOException;

    CredentialIssuerWellKnownResponse getCredentialIssuerWellknown(String issuerId, String search) throws ApiNotAccessibleException, IOException;

    CredentialsSupportedResponse getCredentialSupported(CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse, String credentialType) throws ApiNotAccessibleException, IOException, InvalidCredentialsException;

    VCCredentialResponse downloadCredential(String credentialEndpoint, VCCredentialRequest vcCredentialRequest, String accessToken) throws ApiNotAccessibleException, IOException, InvalidCredentialsException;

    ByteArrayInputStream generatePdfForVerifiableCredentials(VCCredentialResponse vcCredentialResponse, IssuerDTO issuerDTO, CredentialsSupportedResponse credentialsSupportedResponse, String credentialEndPoint) throws Exception;



}
