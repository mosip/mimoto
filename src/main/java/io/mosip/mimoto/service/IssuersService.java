package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.InvalidIssuerIdException;

import java.io.IOException;

public interface IssuersService {
    IssuersDTO getAllIssuers(String search) throws ApiNotAccessibleException, IOException;

    IssuersDTO getAllIssuersWithAllFields() throws ApiNotAccessibleException, IOException;

    IssuerDTO getIssuerConfig(String issuerId) throws ApiNotAccessibleException, IOException, InvalidIssuerIdException;

    CredentialIssuerWellKnownResponse getIssuerWellknown(String issuerId) throws ApiNotAccessibleException, IOException;
}
