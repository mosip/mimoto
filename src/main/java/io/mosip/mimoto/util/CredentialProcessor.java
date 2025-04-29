package io.mosip.mimoto.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dbentity.CredentialMetadata;
import io.mosip.mimoto.dbentity.VerifiableCredential;

import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.IssuerConfig;
import io.mosip.mimoto.dto.mimoto.VCCredentialRequest;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.mimoto.VerifiableCredentialResponseDTO;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.model.QRCodeType;
import io.mosip.mimoto.repository.WalletCredentialsRepository;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.service.impl.DataShareServiceImpl;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.UUID;

import static io.mosip.mimoto.exception.ErrorConstants.*;

/**
 * Utility class for processing and storing credentials.
 */
@Slf4j
@Component
public class CredentialProcessor {

    private final CredentialUtilService credentialUtilService;
    private final DataShareServiceImpl dataShareService;
    private final ObjectMapper objectMapper;
    private final EncryptionDecryptionUtil encryptionDecryptionUtil;
    private final WalletCredentialsRepository walletCredentialsRepository;
    private final IssuersService issuersService;

    @Autowired
    public CredentialProcessor(
            CredentialUtilService credentialUtilService,
            DataShareServiceImpl dataShareService,
            ObjectMapper objectMapper,
            EncryptionDecryptionUtil encryptionDecryptionUtil,
            WalletCredentialsRepository walletCredentialsRepository,
            IssuersService issuersService) {
        this.credentialUtilService = credentialUtilService;
        this.dataShareService = dataShareService;
        this.objectMapper = objectMapper;
        this.encryptionDecryptionUtil = encryptionDecryptionUtil;
        this.walletCredentialsRepository = walletCredentialsRepository;
        this.issuersService = issuersService;
    }

    /**
     * Processes and stores a credential using the provided token and parameters.
     *
     * @param tokenResponse The token response containing the access token.
     * @param credentialType The type of the credential.
     * @param walletId The ID of the wallet.
     * @param base64Key The Base64-encoded wallet key.
     * @param credentialValidity The validity period of the credential.
     * @param issuerId The ID of the issuer.
     * @return The stored VerifiableCredential.
     * @throws InvalidRequestException If input parameters are invalid.
     * @throws CredentialProcessingException If processing fails.
     * @throws ExternalServiceUnavailableException If an external service is unavailable.
     * @throws VCVerificationException If credential verification fails.
     */
    public VerifiableCredentialResponseDTO processAndStoreCredential(
            TokenResponseDTO tokenResponse, String credentialType, String walletId,
            String base64Key, String credentialValidity, String issuerId, String locale)
            throws InvalidRequestException, CredentialProcessingException, ExternalServiceUnavailableException, VCVerificationException {
        // Validate inputs
        if (tokenResponse == null || tokenResponse.getAccess_token() == null) {
            log.error("Invalid token response: null or missing access token");
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Token response or access token cannot be null");
        }
        if (credentialType == null || credentialType.isBlank()) {
            log.error("Invalid credential type: null or blank");
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Credential type cannot be null or blank");
        }
        if (walletId == null || walletId.isBlank()) {
            log.error("Invalid wallet ID: null or blank");
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Wallet ID cannot be null or blank");
        }
        if (base64Key == null || base64Key.isBlank()) {
            log.error("Invalid wallet key: null or blank");
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Wallet key cannot be null or blank");
        }
        if (issuerId == null || issuerId.isBlank()) {
            log.error("Invalid issuer ID: null or blank");
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), "Issuer ID cannot be null or blank");
        }

        // Fetch issuer configuration
        IssuerConfig issuerConfig;
        try {
            issuerConfig = issuersService.getIssuerConfig(issuerId, credentialType);
        } catch (Exception e) {
            log.error("Failed to fetch issuer config for issuerId: {}", issuerId, e);
            throw new CredentialProcessingException(
                    CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(),
                    "Unable to fetch issuer configuration", e);
        }

        // Generate credential request
        VCCredentialRequest vcCredentialRequest;
        try {
            vcCredentialRequest = credentialUtilService.generateVCCredentialRequest(
                    issuerConfig.getIssuerDTO(), issuerConfig.getWellKnownResponse(),
                    issuerConfig.getCredentialsSupportedResponse(), tokenResponse.getAccess_token(),
                    walletId, base64Key, true);
        } catch (Exception e) {
            log.error("Failed to generate VC credential request for issuerId: {}, credentialType: {}", issuerId, credentialType, e);
            throw new CredentialProcessingException(
                    CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(),
                    "Unable to generate credential request", e);
        }

        // Download credential
        VCCredentialResponse vcCredentialResponse;
        try {
            vcCredentialResponse = credentialUtilService.downloadCredential(
                    issuerConfig.getWellKnownResponse().getCredentialEndPoint(),
                    vcCredentialRequest, tokenResponse.getAccess_token());
        } catch (Exception e) {
            log.error("Failed to download credential for issuerId: {}, credentialType: {}", issuerId, credentialType, e);
            throw new ExternalServiceUnavailableException(
                    SERVER_UNAVAILABLE.getErrorCode(),
                    "Unable to download credential from issuer", e);
        }

        // Verify credential
        boolean verificationStatus;
        try {
            verificationStatus = issuerId.toLowerCase().contains("mock") ||
                    credentialUtilService.verifyCredential(vcCredentialResponse);
        } catch (VCVerificationException | JsonProcessingException e) {
            log.error("Credential verification failed for issuerId: {}, credentialType: {}", issuerId, credentialType, e);
            throw new VCVerificationException(
                    SIGNATURE_VERIFICATION_EXCEPTION.getErrorCode(),
                    "Credential verification failed");
        }

        if (!verificationStatus) {
            log.error("Signature verification failed for issuerId: {}, credentialType: {}", issuerId, credentialType);
            throw new VCVerificationException(
                    SIGNATURE_VERIFICATION_EXCEPTION.getErrorCode(),
                    SIGNATURE_VERIFICATION_EXCEPTION.getErrorMessage());
        }

        // Serialize and store credential
        String vcResponseAsJsonString;
        try {
            vcResponseAsJsonString = objectMapper.writeValueAsString(vcCredentialResponse);
        } catch (JsonProcessingException e) {
            log.error("Failed to serialize credential response for issuerId: {}, credentialType: {}", issuerId, credentialType, e);
            throw new CredentialProcessingException(
                    CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(),
                    "Unable to serialize credential response", e);
        }

        String dataShareUrl;
        try {
            dataShareUrl = QRCodeType.OnlineSharing.equals(issuerConfig.getIssuerDTO().getQr_code_type())
                    ? dataShareService.storeDataInDataShare(vcResponseAsJsonString, credentialValidity)
                    : "";
        } catch (Exception e) {
            log.error("Failed to store credential in data share for issuerId: {}, credentialType: {}", issuerId, credentialType, e);
            throw new CredentialProcessingException(
                    CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(),
                    "Unable to store credential in datashare", e);
        }

        String encryptedCredentialData;
        try {
            encryptedCredentialData = encryptionDecryptionUtil.encryptCredential(vcResponseAsJsonString, base64Key);
        } catch (Exception e) {
            log.error("Failed to encrypt credential for issuerId: {}, credentialType: {}", issuerId, credentialType, e);
            throw new CredentialProcessingException(
                    CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(),
                    "Unable to encrypt credential data", e);
        }

        VerifiableCredential savedCredential =  saveCredential(walletId, encryptedCredentialData, issuerId, credentialType, dataShareUrl, credentialValidity);
        return WalletCredentialResponseDTOFactory.buildCredentialResponseDTO(issuerConfig, locale, savedCredential.getId());
    }

    /**
     * Saves the credential to the repository.
     *
     * @param walletId The wallet ID.
     * @param encryptedCredential The encrypted credential data.
     * @param issuerId The issuer ID.
     * @param credentialType The credential type.
     * @param dataShareUrl The data share URL.
     * @param credentialValidity The credential validity.
     * @return The stored VerifiableCredential.
     */
    private VerifiableCredential saveCredential(String walletId, String encryptedCredential, String issuerId,
                                                String credentialType, String dataShareUrl, String credentialValidity) {
        CredentialMetadata credentialMetadata = new CredentialMetadata();
        credentialMetadata.setIssuerId(issuerId);
        credentialMetadata.setCredentialType(credentialType);
        credentialMetadata.setDataShareUrl(dataShareUrl);
        credentialMetadata.setCredentialValidity(credentialValidity);

        VerifiableCredential verifiableCredential = new VerifiableCredential();
        verifiableCredential.setId(UUID.randomUUID().toString());
        verifiableCredential.setWalletId(walletId);
        verifiableCredential.setCredential(encryptedCredential);
        verifiableCredential.setCredentialMetadata(credentialMetadata);

        try {
            return walletCredentialsRepository.save(verifiableCredential);
        } catch (Exception e) {
            log.error("Failed to save credential for walletId: {}, issuerId: {}, credentialType: {}", walletId, issuerId, credentialType, e);
            throw new CredentialProcessingException(
                    CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(),
                    "Unable to save credential to database", e);
        }
    }
}
