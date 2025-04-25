package io.mosip.mimoto.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dbentity.CredentialMetadata;
import io.mosip.mimoto.dbentity.VerifiableCredential;
import io.mosip.mimoto.dto.mimoto.IssuerConfig;
import io.mosip.mimoto.dto.mimoto.VCCredentialRequest;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.exception.CredentialProcessingException;
import io.mosip.mimoto.exception.ExternalServiceUnavailableException;
import io.mosip.mimoto.exception.VCVerificationException;
import io.mosip.mimoto.model.QRCodeType;
import io.mosip.mimoto.repository.WalletCredentialsRepository;
import io.mosip.mimoto.service.impl.DataShareServiceImpl;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.UUID;

import static io.mosip.mimoto.exception.ErrorConstants.*;

@Slf4j
@Component
public class CredentialProcessor {
    @Autowired
    private CredentialUtilService credentialUtilService;

    @Autowired
    private DataShareServiceImpl dataShareService;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    @Autowired
    private WalletCredentialsRepository walletCredentialsRepository;

    public VerifiableCredential processAndStoreCredential(
            IssuerConfig issuerConfig, String accessToken, String credentialType,
            String walletId, String base64EncodedWalletKey, String credentialValidity, String issuerId) throws ExternalServiceUnavailableException {

        // Generate credential request
        VCCredentialRequest vcCredentialRequest;
        try {
            vcCredentialRequest = credentialUtilService.generateVCCredentialRequest(
                    issuerConfig.getIssuerDTO(), issuerConfig.getWellKnownResponse(),
                    issuerConfig.getCredentialsSupportedResponse(), accessToken, walletId, base64EncodedWalletKey, true);
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
                    vcCredentialRequest, accessToken);
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
            encryptedCredentialData = encryptionDecryptionUtil.encryptCredential(vcResponseAsJsonString, base64EncodedWalletKey);
        } catch (Exception e) {
            log.error("Failed to encrypt credential for issuerId: {}, credentialType: {}", issuerId, credentialType, e);
            throw new CredentialProcessingException(
                    CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(),
                    "Unable to encrypt credential data", e);
        }

        return saveCredential(walletId, encryptedCredentialData, issuerId, credentialType, dataShareUrl, credentialValidity);
    }

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

        return walletCredentialsRepository.save(verifiableCredential);
    }
}
