package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.CredentialsSupportedResponse;
import io.mosip.mimoto.dto.mimoto.IssuerConfig;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.dto.mimoto.VerifiableCredentialResponseDTO;
import io.mosip.mimoto.dto.resident.WalletCredentialResponseDTO;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.model.CredentialMetadata;
import io.mosip.mimoto.model.VerifiableCredential;
import io.mosip.mimoto.repository.WalletCredentialsRepository;
import io.mosip.mimoto.service.CredentialPDFGeneratorService;
import io.mosip.mimoto.service.CredentialService;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.service.WalletCredentialService;
import io.mosip.mimoto.util.EncryptionDecryptionUtil;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.InputStreamResource;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import static io.mosip.mimoto.exception.ErrorConstants.*;

/**
 * Implementation of {@link WalletCredentialService} for managing wallet credentials.
 */
@Slf4j
@Service
public class WalletCredentialServiceImpl implements WalletCredentialService {

    @Value("${mosip.inji.wallet.issuersWithSingleVcLimit:Mosip}")
    private String issuersWithSingleVcLimit;

    private final WalletCredentialsRepository repository;
    private final IssuersService issuersService;
    private final CredentialService credentialService;
    private final ObjectMapper objectMapper;
    private final EncryptionDecryptionUtil encryptionDecryptionUtil;
    private final CredentialPDFGeneratorService credentialPDFGeneratorService;

    @Autowired
    public WalletCredentialServiceImpl(WalletCredentialsRepository repository,
                                       IssuersService issuersService,
                                       CredentialService credentialService,
                                       ObjectMapper objectMapper,
                                       EncryptionDecryptionUtil encryptionDecryptionUtil,CredentialPDFGeneratorService credentialPDFGeneratorService) {
        this.repository = repository;
        this.issuersService = issuersService;
        this.credentialService = credentialService;
        this.objectMapper = objectMapper;
        this.encryptionDecryptionUtil = encryptionDecryptionUtil;
        this.credentialPDFGeneratorService = credentialPDFGeneratorService;
    }

    @Override
    public VerifiableCredentialResponseDTO downloadVCAndStoreInDB(String issuerId, String credentialConfigurationId,
                                                                  TokenResponseDTO tokenResponse,
                                                                  String locale, String walletId, String base64Key)
            throws CredentialProcessingException, ExternalServiceUnavailableException {
        log.info("Fetching and storing credential for wallet: {}, issuer: {}, type: {}", walletId, issuerId, credentialConfigurationId);

        Set<String> issuers = Arrays.stream(issuersWithSingleVcLimit.split(","))
                .map(String::trim)
                .collect(Collectors.toSet());
        if (issuers.contains(issuerId) && repository.existsByIssuerIdAndCredentialTypeAndWalletId(issuerId, credentialConfigurationId, walletId)) {
            log.warn("Duplicate credential found for issuer: {}, type: {}, wallet: {}", issuerId, credentialConfigurationId, walletId);
            throw new InvalidRequestException(CREDENTIAL_DOWNLOAD_EXCEPTION.getErrorCode(), "Duplicate credential for issuer and type");
        }


        VerifiableCredentialResponseDTO credential;

        credential = credentialService.downloadCredentialAndStoreInDB(
                tokenResponse, credentialConfigurationId, walletId, base64Key, issuerId, locale);

        log.debug("Credential stored successfully: {}", credential.getCredentialId());
        return credential;

    }

    @Override
    public List<VerifiableCredentialResponseDTO> fetchAllCredentialsForWallet(String walletId, String base64Key, String locale) {
        log.info("Fetching all credentials for wallet: {}", walletId);

        List<VerifiableCredential> credentials = repository.findByWalletIdOrderByCreatedAtDesc(walletId);

        return credentials.stream().map(credential -> {
            String issuerId = credential.getCredentialMetadata().getIssuerId();
            IssuerConfig issuerConfig = null;
            try {
                issuerConfig = issuersService.getIssuerConfig(issuerId, credential.getCredentialMetadata().getCredentialType());
            } catch (InvalidIssuerIdException | ApiNotAccessibleException  e) {
                log.error("Failed to fetch issuer details for issuerId: {}", issuerId, e);
            }
            return VerifiableCredentialResponseDTO.fromIssuerConfig(issuerConfig, locale, credential.getId());
        }).toList();

    }

    @Override
    public WalletCredentialResponseDTO fetchVerifiableCredential(String walletId, String credentialId,
                                                                 String base64Key, String locale)
            throws CredentialNotFoundException, CredentialProcessingException {
        log.info("Fetching credential: {} for wallet: {}", credentialId, walletId);
        VerifiableCredential credential = repository.findByIdAndWalletId(credentialId, walletId)
                .orElseThrow(getCredentialNotFoundExceptionSupplier(walletId, credentialId));

        try {
            String decryptedCredential = encryptionDecryptionUtil.decryptCredential(credential.getCredential(), base64Key);

            WalletCredentialResponseDTO response = generateCredentialResponse(decryptedCredential, credential.getCredentialMetadata(), locale);
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

        repository.findByIdAndWalletId(credentialId, walletId)
                .orElseThrow(getCredentialNotFoundExceptionSupplier(walletId, credentialId));
        // Delete the credential
        repository.deleteById(credentialId);
        log.info("Successfully deleted credential with ID: {}", credentialId);
    }

    @NotNull
    private static Supplier<CredentialNotFoundException> getCredentialNotFoundExceptionSupplier(String walletId, String credentialId) {
        return () -> {
            log.warn("Credential not found: {} for wallet: {}", credentialId, walletId);
            return new CredentialNotFoundException(RESOURCE_NOT_FOUND.getErrorCode(), RESOURCE_NOT_FOUND.getErrorMessage());
        };
    }

    private WalletCredentialResponseDTO generateCredentialResponse(String decryptedCredential, CredentialMetadata credentialMetadata, String locale) throws CredentialProcessingException {
        log.info("Generating credential response for issuerId: {}, credentialType: {}", credentialMetadata.getIssuerId(), credentialMetadata.getCredentialType());
        try {
            // Parse decrypted credential
            VCCredentialResponse vcCredentialResponse = objectMapper.readValue(decryptedCredential, VCCredentialResponse.class);

            // Fetch issuer details
            IssuerDTO issuerDTO = issuersService.getIssuerDetails(credentialMetadata.getIssuerId());

            // Fetch issuer configuration
            IssuerConfig issuerConfig = issuersService.getIssuerConfig(credentialMetadata.getIssuerId(), credentialMetadata.getCredentialType());

            if (null == issuerConfig) {
                log.error("Credentials supported response not found in wellknown for credentialType: {}", credentialMetadata.getCredentialType());
                throw new CredentialProcessingException(CREDENTIAL_FETCH_EXCEPTION.getErrorCode(), "Invalid credential type configuration");
            }

            // Find credentials supported response for the credential type
            CredentialsSupportedResponse credentialsSupportedResponse = issuerConfig.getCredentialsSupportedResponse();
            if (credentialsSupportedResponse == null ) {
                log.error("Credentials supported response not found for credentialType: {}", credentialMetadata.getCredentialType());
                throw new CredentialProcessingException(CREDENTIAL_FETCH_EXCEPTION.getErrorCode(), "Invalid credential type configuration");
            }

            // Generate PDF
            // keep the datashare url and credential validity as defaults in downloading VC as PDF as logged-in user
            // This is because generatePdfForVerifiableCredentials will be used by both logged-in and non-logged-in users
            ByteArrayInputStream pdfStream = credentialPDFGeneratorService.generatePdfForVerifiableCredentials(
                    credentialMetadata.getCredentialType(),
                    vcCredentialResponse,
                    issuerDTO,
                    credentialsSupportedResponse,
                    "",
                    "-1",
                    locale
            );

            // Construct response
            String fileName = String.format("%s_credential.pdf", credentialMetadata.getCredentialType());
            return WalletCredentialResponseDTO.builder()
                    .fileName(fileName)
                    .fileContentStream(new InputStreamResource(pdfStream))
                    .build();
        } catch (JsonProcessingException e) {
            log.error("Failed to parse decrypted credential for issuerId: {}, credentialType: {}", credentialMetadata.getIssuerId(), credentialMetadata.getCredentialType(), e);
            throw new CredentialProcessingException(CREDENTIAL_FETCH_EXCEPTION.getErrorCode(), "Failed to parse decrypted credential");
        } catch (ApiNotAccessibleException | IOException | AuthorizationServerWellknownResponseException |
                 InvalidWellknownResponseException | InvalidIssuerIdException e) {
            log.error("Failed to fetch issuer details or configuration for issuerId: {}", credentialMetadata.getIssuerId(), e);
            throw new CredentialProcessingException(CREDENTIAL_FETCH_EXCEPTION.getErrorCode(), "Failed to fetch issuer configuration");
        } catch (Exception e) {
            log.error("Failed to generate PDF for credentialType: {}", credentialMetadata.getCredentialType(), e);
            throw new CredentialProcessingException(CREDENTIAL_FETCH_EXCEPTION.getErrorCode(), "Failed to generate credential PDF");
        }
    }
}