package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.kernel.cryptomanager.service.CryptomanagerService;
import io.mosip.mimoto.dbentity.VerifiableCredential;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.dto.resident.WalletCredentialResponseDTO;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.repository.WalletCredentialsRepository;
import io.mosip.mimoto.service.IdpService;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.service.WalletCredentialService;
import io.mosip.mimoto.util.CredentialProcessor;
import io.mosip.mimoto.util.CredentialUtilService;
import io.mosip.mimoto.util.EncryptionDecryptionUtil;
import io.mosip.mimoto.util.WalletCredentialResponseDTOFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.InputStreamResource;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static io.mosip.mimoto.exception.ErrorConstants.*;
import static io.mosip.mimoto.util.LocaleUtils.getCredentialDisplayDTOBasedOnLocale;

@Slf4j
@Service
public class WalletCredentialServiceImpl implements WalletCredentialService {
    @Autowired
    private IssuersService issuersService;

    @Autowired
    private DataShareServiceImpl dataShareService;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private IdpService idpService;

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private PresentationServiceImpl presentationService;

    @Autowired
    private CryptomanagerService cryptomanagerService;

    @Autowired
    private WalletCredentialsRepository walletCredentialsRepository;

    @Autowired
    private CredentialUtilService credentialUtilService;

    @Autowired
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    @Autowired
    private CredentialProcessor credentialProcessor;

    @Override
    public VerifiableCredentialResponseDTO fetchAndStoreCredential(
            String issuerId, String credentialType, TokenResponseDTO response,
            String credentialValidity, String locale, String walletId, String base64EncodedWalletKey) throws ExternalServiceUnavailableException {

        shouldInitiateDownloadRequest(issuerId, credentialType, walletId);

        IssuerConfig issuerConfig = fetchIssuerConfig(issuerId, credentialType);

        VerifiableCredential savedCredential = credentialProcessor.processAndStoreCredential(
                issuerConfig, response.getAccess_token(), credentialType, walletId,
                base64EncodedWalletKey, credentialValidity, issuerId);

        return WalletCredentialResponseDTOFactory.buildCredentialResponseDTO(
                issuerConfig.getIssuerDTO(), issuerConfig.getCredentialsSupportedResponse(), locale, savedCredential.getId());
    }

    private void shouldInitiateDownloadRequest(String issuerId, String credentialType, String walletId) {
        Set<String> issuers = Set.of("Mosip");
        if (issuers.contains(issuerId) && alreadyDownloaded(issuerId, credentialType, walletId)) {
            throw new InvalidRequestException(
                    INVALID_REQUEST.getErrorCode(),
                    "A credential is already downloaded for the selected Issuer and Credential Type. Only one is allowed");
        }
    }

    private boolean alreadyDownloaded(String issuerId, String credentialType, String walletId) {
        return walletCredentialsRepository.existsByIssuerIdAndCredentialTypeAndWalletId(issuerId, credentialType, walletId);
    }

    private IssuerConfig fetchIssuerConfig(String issuerId, String credentialType) throws ExternalServiceUnavailableException {
        IssuerDTO issuerDTO;
        try {
            issuerDTO = issuersService.getIssuerDetails(issuerId);
        } catch (ApiNotAccessibleException | IOException | AuthorizationServerWellknownResponseException |
                 InvalidWellknownResponseException e) {
            log.error("Failed to fetch issuer details for issuerId: {}", issuerId, e);
            throw new ExternalServiceUnavailableException(SERVER_UNAVAILABLE.getErrorCode(), "Unable to fetch issuer details due to a service error", e);
        } catch (InvalidIssuerIdException e) {
            log.error("Invalid issuerId: {}", issuerId, e);
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), e.getMessage(), e);
        }

        CredentialIssuerWellKnownResponse wellKnownResponse;
        try {
            wellKnownResponse = getIssuerWellKnownResponse(issuerId);
        } catch (AuthorizationServerWellknownResponseException | ApiNotAccessibleException | IOException |
                 InvalidWellknownResponseException e) {
            log.error("Failed to fetch issuer well-known response for issuerId: {}", issuerId, e);
            throw new ExternalServiceUnavailableException(SERVER_UNAVAILABLE.getErrorCode(), "Unable to fetch issuer configuration", e);
        }

        CredentialsSupportedResponse credentialsSupportedResponse = wellKnownResponse.getCredentialConfigurationsSupported().get(credentialType);
        if (credentialsSupportedResponse == null) {
            log.error("Credential type {} not supported for issuerId: {}", credentialType, issuerId);
            throw new InvalidRequestException(INVALID_REQUEST.getErrorCode(), String.format("Credential type %s is not supported by issuer %s", credentialType, issuerId));
        }

        return new IssuerConfig(issuerDTO, wellKnownResponse, credentialsSupportedResponse);
    }

    @Override
    public List<VerifiableCredentialResponseDTO> fetchAllCredentialsForWallet(String walletId, String walletKey, String locale) {
        List<VerifiableCredential> credentials = walletCredentialsRepository.findByWalletId(walletId);

        return credentials.stream().map(credentialRecord -> {
            try {
                String issuerId = credentialRecord.getCredentialMetadata().getIssuerId();
                IssuerConfig issuerConfig = fetchIssuerConfig(issuerId, credentialRecord.getCredentialMetadata().getCredentialType());
                return WalletCredentialResponseDTOFactory.buildCredentialResponseDTO(
                        issuerConfig.getIssuerDTO(), issuerConfig.getCredentialsSupportedResponse(), locale, credentialRecord.getId());
            } catch (Exception e) {
                log.info("Error occurred while fetching configuration of issuerId: {} for credentialId: {}",
                        credentialRecord.getCredentialMetadata().getIssuerId(), credentialRecord.getId(), e);
                return WalletCredentialResponseDTOFactory.buildCredentialResponseDTO(null, null, locale, credentialRecord.getId());
            }
        }).toList();
    }

    @Override
    public WalletCredentialResponseDTO fetchVerifiableCredential(String walletId, String credentialId, String base64EncodedWalletKey, String locale)
            throws DecryptionException, CorruptedEncryptedDataException, ExternalServiceUnavailableException {
        Optional<VerifiableCredential> verifiableCredentialObj = walletCredentialsRepository.findByIdAndWalletId(credentialId, walletId);
        VerifiableCredential verifiableCredential;
        if (verifiableCredentialObj.isEmpty()) {
            log.error("Credential not found for walletId: {} and credentialId: {}", walletId, credentialId);
            throw new CredentialNotFoundException(RESOURCE_NOT_FOUND.getErrorCode(), RESOURCE_NOT_FOUND.getErrorMessage());
        }
        verifiableCredential = verifiableCredentialObj.get();

        String decryptCredentialResponse = encryptionDecryptionUtil.decryptCredential(verifiableCredential.getCredential(), base64EncodedWalletKey);
        String issuerId = verifiableCredential.getCredentialMetadata().getIssuerId();
        String credentialType = verifiableCredential.getCredentialMetadata().getCredentialType();
        String dataShareUrl = verifiableCredential.getCredentialMetadata().getDataShareUrl();
        String credentialValidity = verifiableCredential.getCredentialMetadata().getCredentialValidity();

        IssuerConfig issuerConfig = fetchIssuerConfig(issuerId, credentialType);

        VCCredentialResponse vcCredentialResponse;
        try {
            vcCredentialResponse = objectMapper.readValue(decryptCredentialResponse, VCCredentialResponse.class);
        } catch (JsonProcessingException e) {
            log.error("Error occurred while parsing the decrypted credential response", e);
            throw new CorruptedEncryptedDataException(SCHEMA_MISMATCH.getErrorCode(), SCHEMA_MISMATCH.getErrorMessage(), e);
        }

        ByteArrayInputStream byteArrayInputStream;
        try {
            byteArrayInputStream = credentialUtilService.generatePdfForVerifiableCredentials(
                    credentialType, vcCredentialResponse, issuerConfig.getIssuerDTO(),
                    issuerConfig.getCredentialsSupportedResponse(), dataShareUrl, credentialValidity, locale);
        } catch (Exception e) {
            log.error("Error occurred while creating pdf", e);
            throw new CredentialPdfGenerationException(
                    SERVER_UNAVAILABLE.getErrorCode(),
                    SERVER_UNAVAILABLE.getErrorMessage());
        }
        String fileName = getCredentialDisplayDTOBasedOnLocale(issuerConfig.getCredentialsSupportedResponse().getDisplay(), locale).getName();

        return new WalletCredentialResponseDTO(new InputStreamResource(byteArrayInputStream), fileName);
    }

    private CredentialIssuerWellKnownResponse getIssuerWellKnownResponse(String issuerId) throws AuthorizationServerWellknownResponseException, ApiNotAccessibleException, IOException, InvalidWellknownResponseException {
        CredentialIssuerConfiguration credentialIssuerConfiguration = issuersService.getIssuerConfiguration(issuerId);
        return new CredentialIssuerWellKnownResponse(
                credentialIssuerConfiguration.getCredentialIssuer(),
                credentialIssuerConfiguration.getAuthorizationServers(),
                credentialIssuerConfiguration.getCredentialEndPoint(),
                credentialIssuerConfiguration.getCredentialConfigurationsSupported()
        );
    }

}