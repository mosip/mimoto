package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.dbentity.VerifiableCredential;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.IssuerConfig;
import io.mosip.mimoto.dto.mimoto.VerifiableCredentialResponseDTO;
import io.mosip.mimoto.dto.resident.WalletCredentialResponseDTO;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.repository.WalletCredentialsRepository;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.service.WalletCredentialService;
import io.mosip.mimoto.util.CredentialProcessor;
import io.mosip.mimoto.util.CredentialUtilService;
import io.mosip.mimoto.util.EncryptionDecryptionUtil;
import io.mosip.mimoto.util.WalletCredentialResponseDTOFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static io.mosip.mimoto.exception.ErrorConstants.*;

/**
 * Implementation of {@link WalletCredentialService} for managing wallet credentials.
 */
@Slf4j
@Service
public class WalletCredentialServiceImpl implements WalletCredentialService {
    private final WalletCredentialsRepository repository;
    private final IssuersService issuersService;
    private final CredentialProcessor credentialProcessor;
    private final CredentialUtilService credentialUtilService;
    private final EncryptionDecryptionUtil encryptionDecryptionUtil;

    @Autowired
    public WalletCredentialServiceImpl(WalletCredentialsRepository repository,
                                       IssuersService issuersService,
                                       CredentialProcessor credentialProcessor,
                                       CredentialUtilService credentialUtilService,
                                       EncryptionDecryptionUtil encryptionDecryptionUtil) {
        this.repository = repository;
        this.issuersService = issuersService;
        this.credentialProcessor = credentialProcessor;
        this.credentialUtilService = credentialUtilService;
        this.encryptionDecryptionUtil = encryptionDecryptionUtil;
    }

    @Override
    public VerifiableCredentialResponseDTO fetchAndStoreCredential(String issuerId, String credentialConfigurationId,
                                                                   TokenResponseDTO tokenResponse, String credentialValidity,
                                                                   String locale, String walletId, String base64Key)
            throws CredentialProcessingException, ExternalServiceUnavailableException {
        log.info("Fetching and storing credential for wallet: {}, issuer: {}, type: {}", walletId, issuerId, credentialConfigurationId);

        Set<String> issuers = Set.of("Mosip");
        if (issuers.contains(issuerId)){
            if (repository.existsByIssuerIdAndCredentialTypeAndWalletId(issuerId, credentialConfigurationId, walletId)) {
                log.warn("Duplicate credential found for issuer: {}, type: {}, wallet: {}", issuerId, credentialConfigurationId, walletId);
                throw new CredentialProcessingException(CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(), "Duplicate credential for issuer and type");
            }
        }

        VerifiableCredentialResponseDTO credential = null;

            credential = credentialProcessor.processAndStoreCredential(
                    tokenResponse, credentialConfigurationId, walletId, base64Key, credentialValidity, issuerId, locale);

        log.debug("Credential stored successfully: {}", credential.getCredentialId());
            return credential;

    }

    @Override
    public List<VerifiableCredentialResponseDTO> fetchAllCredentialsForWallet(String walletId, String base64Key, String locale) {
        log.info("Fetching all credentials for wallet: {}", walletId);

        List<VerifiableCredential> credentials = repository.findByWalletId(walletId);

        return credentials.stream().map(credential -> {
            String issuerId = credential.getCredentialMetadata().getIssuerId();
            IssuerConfig issuerConfig = null;
            try {
                issuerConfig = issuersService.getIssuerConfig(issuerId, credential.getCredentialMetadata().getCredentialType());
            } catch (ApiNotAccessibleException | IOException | AuthorizationServerWellknownResponseException |
                     InvalidWellknownResponseException e) {
                log.error("Failed to fetch issuer details for issuerId: {}", issuerId, e);
            }
            return WalletCredentialResponseDTOFactory.buildCredentialResponseDTO(issuerConfig, locale, credential.getId());
        }).collect(Collectors.toList());

    }

    @Override
    public WalletCredentialResponseDTO fetchVerifiableCredential(String walletId, String credentialId,
                                                                 String base64Key, String locale)
            throws CredentialNotFoundException, CredentialProcessingException {
        log.info("Fetching credential: {} for wallet: {}", credentialId, walletId);
        VerifiableCredential credential = repository.findByIdAndWalletId(credentialId, walletId)
                .orElseThrow(() -> {
                    log.warn("Credential not found: {} for wallet: {}", credentialId, walletId);
                    return new CredentialNotFoundException(RESOURCE_NOT_FOUND.getErrorCode(), RESOURCE_NOT_FOUND.getErrorMessage());
                });

        try {
            String decryptedCredential = encryptionDecryptionUtil.decryptCredential(credential.getCredential(), base64Key);
            WalletCredentialResponseDTO response = credentialUtilService.generateCredentialResponse(
                    decryptedCredential, credential.getCredentialMetadata(), locale);
            log.debug("Credential fetched successfully: {}", credentialId);
            return response;
        } catch (DecryptionException e) {
            log.error("Decryption failed for credential: {}", credentialId, e);
            throw new CredentialProcessingException(CREDENTIAL_FETCH_EXCEPTION.getErrorCode(), "Decryption failed", e);
        }
    }

    @Override
    public void deleteCredential(String credentialId, String walletId) throws CredentialNotFoundException {
        log.info("Deleting credential with ID: {} for wallet: {}", credentialId, walletId);

        VerifiableCredential credential = repository.findByIdAndWalletId(credentialId, walletId)
                .orElseThrow(() -> {
                    log.warn("Credential not found: {} for wallet: {}", credentialId, walletId);
                    return new CredentialNotFoundException(RESOURCE_NOT_FOUND.getErrorCode(), RESOURCE_NOT_FOUND.getErrorMessage());
                });
        // Delete the credential
        repository.deleteById(credentialId);
        log.info("Successfully deleted credential with ID: {}", credentialId);
    }

}