package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.VCCredentialRequest;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.mimoto.VerifiableCredentialResponseDTO;
import io.mosip.mimoto.exception.*;

import java.io.ByteArrayInputStream;

public interface CredentialService {

    /**
     * Downloads credential as PDF.
     *
     * @param issuerId           The issuer ID
     * @param credentialType     The credential type
     * @param response           The token response
     * @param credentialValidity The credential validity
     * @param locale             The locale
     * @return ByteArrayInputStream containing the PDF
     * @throws Exception If any error occurs during processing
     */
    ByteArrayInputStream downloadCredentialAsPDF(String issuerId, String credentialType, TokenResponseDTO response, String credentialValidity, String locale) throws Exception;

    /**
     * Downloads credential from the issuer endpoint.
     *
     * @param credentialEndpoint The credential endpoint
     * @param vcCredentialRequest The credential request
     * @param accessToken The access token
     * @return VCCredentialResponse containing the credential
     * @throws InvalidCredentialResourceException If the credential resource is invalid
     */
    VCCredentialResponse downloadCredential(String credentialEndpoint, VCCredentialRequest vcCredentialRequest, String accessToken) throws InvalidCredentialResourceException;

    /**
     * Downloads credential and stores it in the database.
     *
     * @param tokenResponse             The token response containing the access token
     * @param credentialConfigurationId The type of the credential
     * @param walletId                  The ID of the wallet
     * @param base64Key                 The Base64-encoded wallet key
     * @param issuerId                  The ID of the issuer
     * @param locale                    The locale for the response
     * @return The stored VerifiableCredential response
     * @throws InvalidRequestException             If input parameters are invalid
     * @throws CredentialProcessingException       If processing fails
     * @throws ExternalServiceUnavailableException If an external service is unavailable
     * @throws VCVerificationException             If credential verification fails
     */
    VerifiableCredentialResponseDTO downloadCredentialAndStoreInDB(
            TokenResponseDTO tokenResponse, String credentialConfigurationId, String walletId,
            String base64Key, String issuerId, String locale)
            throws InvalidRequestException, CredentialProcessingException, ExternalServiceUnavailableException, VCVerificationException;
}