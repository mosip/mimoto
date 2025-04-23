package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.kernel.cryptomanager.service.CryptomanagerService;
import io.mosip.mimoto.dbentity.CredentialMetadata;
import io.mosip.mimoto.dbentity.VerifiableCredential;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.dto.resident.WalletCredentialResponseDTO;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.model.QRCodeType;
import io.mosip.mimoto.repository.WalletCredentialsRepository;
import io.mosip.mimoto.service.IdpService;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.service.WalletCredentialService;
import io.mosip.mimoto.util.*;
import io.mosip.pixelpass.PixelPass;
import io.mosip.vercred.vcverifier.CredentialsVerifier;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.InputStreamResource;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.*;

import static io.mosip.mimoto.exception.ErrorConstants.*;
import static io.mosip.mimoto.util.LocaleUtils.getCredentialDisplayDTOBasedOnLocale;


@Slf4j
@Service
public class WalletCredentialServiceImpl implements WalletCredentialService {
    @Autowired
    IssuersService issuersService;

    @Autowired
    DataShareServiceImpl dataShareService;

    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    IdpService idpService;

    @Autowired
    RestTemplate restTemplate;

    @Value("${mosip.inji.ovp.qrdata.pattern}")
    String ovpQRDataPattern;

    @Value("${mosip.inji.qr.code.height:500}")
    Integer qrCodeHeight;

    @Value("${mosip.inji.qr.code.width:500}")
    Integer qrCodeWidth;

    @Value("${mosip.inji.qr.data.size.limit:2000}")
    Integer allowedQRDataSizeLimit;

    @Autowired
    PresentationServiceImpl presentationService;

    @Autowired
    private CryptomanagerService cryptomanagerService;

    @Autowired
    private WalletCredentialsRepository walletCredentialsRepository;

    @Autowired
    private CredentialUtilService credentialUtilService;

    @Autowired
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    PixelPass pixelPass;
    CredentialsVerifier credentialsVerifier;

    @PostConstruct
    public void init() {
        pixelPass = new PixelPass();
        credentialsVerifier = new CredentialsVerifier();
    }

    @Override
    public VerifiableCredentialResponseDTO fetchAndStoreCredential(
            String issuerId, String credentialType, TokenResponseDTO response,
            String credentialValidity, String locale, String walletId, String base64EncodedWalletKey) throws Exception {

        shouldInitiateDownloadRequest(issuerId, credentialType, walletId);

        IssuerDTO issuerDTO = issuersService.getIssuerDetails(issuerId);
        CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse = getIssuerWellKnownResponse(issuerId);
        CredentialsSupportedResponse credentialsSupportedResponse = credentialIssuerWellKnownResponse.getCredentialConfigurationsSupported().get(credentialType);

        VCCredentialRequest vcCredentialRequest = credentialUtilService.generateVCCredentialRequest(issuerDTO, credentialIssuerWellKnownResponse, credentialsSupportedResponse, response.getAccess_token(), walletId, base64EncodedWalletKey, true);
        VCCredentialResponse vcCredentialResponse = credentialUtilService.downloadCredential(credentialIssuerWellKnownResponse.getCredentialEndPoint(), vcCredentialRequest, response.getAccess_token());
        boolean verificationStatus = issuerId.toLowerCase().contains("mock") || credentialUtilService.verifyCredential(vcCredentialResponse);

        if (!verificationStatus) {
            throw new VCVerificationException(SIGNATURE_VERIFICATION_EXCEPTION.getErrorCode(),
                    SIGNATURE_VERIFICATION_EXCEPTION.getErrorMessage());
        }

        String dataShareUrl = QRCodeType.OnlineSharing.equals(issuerDTO.getQr_code_type()) ? dataShareService.storeDataInDataShare(objectMapper.writeValueAsString(vcCredentialResponse), credentialValidity) : "";
        String vcResponseAsJsonString = objectMapper.writeValueAsString(vcCredentialResponse);
        String encryptedCredentialData = encryptionDecryptionUtil.encryptCredential(vcResponseAsJsonString, base64EncodedWalletKey);
        VerifiableCredential savedCredential = saveCredential(walletId, encryptedCredentialData, issuerId, credentialType, dataShareUrl, credentialValidity);

        return WalletCredentialResponseDTOFactory.buildCredentialResponseDTO(issuerDTO, credentialsSupportedResponse, locale, savedCredential.getId());
    }

    private void shouldInitiateDownloadRequest(String issuerId, String credentialType, String walletId) {
        Set<String> issuers = Set.of("Mosip");
        if (issuers.contains(issuerId) && alreadyDownloaded(issuerId, credentialType, walletId)) {
            throw new RuntimeException("A credential is already downloaded for the selected Issuer and Credential Type. Only one is allowed, so download will not be initiated");
        }
    }

    private boolean alreadyDownloaded(String issuerId, String credentialType, String walletId) {
        return walletCredentialsRepository.existsByIssuerIdAndCredentialTypeAndWalletId(issuerId, credentialType, walletId);
    }

    @Override
    public List<VerifiableCredentialResponseDTO> fetchAllCredentialsForWallet(String walletId, String walletKey, String locale) {
        List<VerifiableCredential> credentials = walletCredentialsRepository.findByWalletId(walletId);

        return credentials.stream().map(credentialRecord -> {
            try {
                String issuerId = credentialRecord.getCredentialMetadata().getIssuerId();
                IssuerDTO issuerDTO = issuersService.getIssuerDetails(issuerId);
                CredentialIssuerWellKnownResponse wellKnownResponse = getIssuerWellKnownResponse(issuerId);
                CredentialsSupportedResponse credentialsSupportedResponse = wellKnownResponse
                        .getCredentialConfigurationsSupported()
                        .get(credentialRecord.getCredentialMetadata().getCredentialType());

                return WalletCredentialResponseDTOFactory.buildCredentialResponseDTO(issuerDTO, credentialsSupportedResponse, locale, credentialRecord.getId());
            } catch (Exception e) {
                log.info("Error occurred while fetching configuration of issuerId : {} for credentialId: {}",
                        credentialRecord.getCredentialMetadata().getIssuerId(), credentialRecord.getId(), e);
                return WalletCredentialResponseDTOFactory.buildCredentialResponseDTO(null, null, locale, credentialRecord.getId());
            }
        }).toList();
    }

    @Override
    public WalletCredentialResponseDTO fetchVerifiableCredential(String walletId, String credentialId, String base64EncodedWalletKey, String locale) throws DecryptionException, CorruptedEncryptedDataException {
        Optional<VerifiableCredential> verifiableCredentialObj = walletCredentialsRepository.findByIdAndWalletId(credentialId, walletId);
        VerifiableCredential verifiableCredential;
        if (verifiableCredentialObj.isPresent()) {
            verifiableCredential = verifiableCredentialObj.get();
        } else {
            throw new InvalidInputException(INVALID_REQUEST.getErrorCode(), "Credential not found");
        }

        String decryptCredentialResponse = encryptionDecryptionUtil.decryptCredential(verifiableCredential.getCredential(), base64EncodedWalletKey);
        String issuerId = verifiableCredential.getCredentialMetadata().getIssuerId();
        String credentialType = verifiableCredential.getCredentialMetadata().getCredentialType();
        String dataShareUrl = verifiableCredential.getCredentialMetadata().getDataShareUrl();
        String credentialValidity = verifiableCredential.getCredentialMetadata().getCredentialValidity();
        IssuerDTO issuerDTO = null;
        CredentialIssuerConfiguration credentialIssuerConfiguration = null;
        try {
            issuerDTO = issuersService.getIssuerDetails(issuerId);
            credentialIssuerConfiguration = issuersService.getIssuerConfiguration(issuerId);
        } catch (ApiNotAccessibleException | IOException | AuthorizationServerWellknownResponseException |
                 InvalidWellknownResponseException e) {
            log.error("Error occurred while fetching issuer configuration for issuerId: {}", issuerId, e);
            throw new ExternalServiceUnavailableException(
                    ErrorConstants.SERVER_UNAVAILABLE.getErrorCode(),
                    ErrorConstants.SERVER_UNAVAILABLE.getErrorMessage());
        }


        CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse = new CredentialIssuerWellKnownResponse(
                credentialIssuerConfiguration.getCredentialIssuer(),
                credentialIssuerConfiguration.getAuthorizationServers(),
                credentialIssuerConfiguration.getCredentialEndPoint(),
                credentialIssuerConfiguration.getCredentialConfigurationsSupported());
        CredentialsSupportedResponse credentialsSupportedResponse = credentialIssuerWellKnownResponse.getCredentialConfigurationsSupported().get(credentialType);

        VCCredentialResponse vcCredentialResponse = null;
        try {
            vcCredentialResponse = objectMapper.readValue(decryptCredentialResponse, VCCredentialResponse.class);
        } catch (JsonProcessingException e) {
            throw new CorruptedEncryptedDataException(SCHEMA_MISMATCH.getErrorCode(), SCHEMA_MISMATCH.getErrorMessage(), e);
        }
        ByteArrayInputStream byteArrayInputStream = null;
        try {
            byteArrayInputStream = credentialUtilService.generatePdfForVerifiableCredentials(credentialType, vcCredentialResponse, issuerDTO, credentialsSupportedResponse, dataShareUrl, credentialValidity, locale);
        } catch (Exception e) {
            log.error("Error occurred while creating pdf", e);
            throw new CredentialPdfGenerationException(
                    ErrorConstants.SERVER_UNAVAILABLE.getErrorCode(),
                    ErrorConstants.SERVER_UNAVAILABLE.getErrorMessage());
        }
        String fileName = getCredentialDisplayDTOBasedOnLocale(credentialsSupportedResponse.getDisplay(), locale).getName();

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

    private VerifiableCredential saveCredential(String walletId, String encryptedCredential, String issuerId, String credentialType, String dataShareUrl, String credentialValidity) {
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
