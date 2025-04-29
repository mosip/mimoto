package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.VerifiableCredentialResponseDTO;
import io.mosip.mimoto.dto.resident.WalletCredentialResponseDTO;
import io.mosip.mimoto.exception.*;

import java.util.List;

/**
 * Service interface for managing wallet credentials.
 */
public interface WalletCredentialService {

    /**
     * Fetches and stores a credential for a wallet.
     *
     * @param issuerId       The issuer ID.
     * @param credentialType The type of credential.
     * @param tokenResponse  The token response containing the access token.
     * @param credentialValidity The validity period of the credential.
     * @param locale         The locale for display purposes.
     * @param walletId       The wallet ID.
     * @param base64Key      The base64-encoded key for encryption.
     * @return The stored credential response.
     * @throws CredentialProcessingException If processing fails.
     */
    VerifiableCredentialResponseDTO fetchAndStoreCredential(String issuerId, String credentialType,
                                                            TokenResponseDTO tokenResponse, String credentialValidity,
                                                            String locale, String walletId, String base64Key)
            throws CredentialProcessingException, ExternalServiceUnavailableException;

    /**
     * Fetches all credentials for a wallet.
     *
     * @param walletId  The wallet ID.
     * @param base64Key The base64-encoded key for decryption.
     * @param locale    The locale for display purposes.
     * @return List of credential responses.
     */
    List<VerifiableCredentialResponseDTO> fetchAllCredentialsForWallet(String walletId, String base64Key, String locale);

    /**
     * Fetches a single verifiable credential by ID.
     *
     * @param walletId     The wallet ID.
     * @param credentialId The credential ID.
     * @param base64Key    The base64-encoded key for decryption.
     * @param locale       The locale for display purposes.
     * @return The credential response with PDF stream.
     * @throws CredentialNotFoundException If the credential is not found.
     * @throws CredentialProcessingException If processing fails.
     */
    WalletCredentialResponseDTO fetchVerifiableCredential(String walletId, String credentialId, String base64Key,
                                                          String locale)
            throws CredentialNotFoundException, CredentialProcessingException;
}
