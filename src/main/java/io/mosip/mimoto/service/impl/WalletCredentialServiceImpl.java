package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.kernel.cryptomanager.service.CryptomanagerService;
import io.mosip.mimoto.dbentity.CredentialMetadata;
import io.mosip.mimoto.dbentity.VerifiableCredential;
import io.mosip.mimoto.dto.DisplayDTO;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.AuthorizationServerWellknownResponseException;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
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
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static io.mosip.mimoto.util.LocaleUtils.getCredentialDisplayDTOBasedOnLocale;
import static io.mosip.mimoto.util.LocaleUtils.getIssuerDisplayDTOBasedOnLocale;

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
            String credentialValidity, String locale, String walletId, String walletKey) throws Exception {

        // Fetch issuer configuration
        IssuerDTO issuerDTO = issuersService.getIssuerDetails(issuerId);
        CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse = getIssuerWellKnownResponse(issuerId);
        CredentialsSupportedResponse credentialsSupportedResponse = credentialIssuerWellKnownResponse.getCredentialConfigurationsSupported().get(credentialType);

        // Generate credential request and download credential
        VCCredentialRequest vcCredentialRequest = credentialUtilService.generateVCCredentialRequest(issuerDTO, credentialIssuerWellKnownResponse, credentialsSupportedResponse, response.getAccess_token());
        VCCredentialResponse vcCredentialResponse = credentialUtilService.downloadCredential(credentialIssuerWellKnownResponse.getCredentialEndPoint(), vcCredentialRequest, response.getAccess_token());
        boolean verificationStatus = issuerId.toLowerCase().contains("mock") || credentialUtilService.verifyCredential(vcCredentialResponse);

        // Encrypt and store credential response into database
        String encryptedCredentialData = encryptCredential(vcCredentialResponse.toString(), walletKey);
        VerifiableCredential savedCredential = saveCredential(walletId, encryptedCredentialData, verificationStatus, issuerId, credentialType );

        // Build and return response DTO
        return buildCredentialResponseDTO(issuerDTO, credentialsSupportedResponse, locale, savedCredential.getId());
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

                return buildCredentialResponseDTO(issuerDTO, credentialsSupportedResponse, locale, credentialRecord.getId());
            } catch (Exception e) {
                log.info("Error occurred while fetching configuration of issuerId : {} for credentialId: {}",
                        credentialRecord.getCredentialMetadata().getIssuerId(), credentialRecord.getId(), e);
                return buildCredentialResponseDTO(null, null, locale, credentialRecord.getId());
            }
        }).toList();
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

    private String encryptCredential(String credentialData, String base64EncodedWalletKey) throws Exception {
        byte[] decodedWalletKey = Base64.getDecoder().decode(base64EncodedWalletKey);
        SecretKey walletKey = EncryptionDecryptionUtil.bytesToSecretKey(decodedWalletKey);
        return encryptionDecryptionUtil.encryptWithAES(walletKey, EncryptionDecryptionUtil.stringToBytes(credentialData));
    }

    private String decryptCredential(String encryptedCredentialData, String base64EncodedWalletKey) throws Exception {
        byte[] decodedWalletKey = Base64.getDecoder().decode(base64EncodedWalletKey);
        SecretKey walletKey = EncryptionDecryptionUtil.bytesToSecretKey(decodedWalletKey);
        return EncryptionDecryptionUtil.bytesToString(encryptionDecryptionUtil.decryptWithAES(walletKey, encryptedCredentialData));
    }

    private VerifiableCredential saveCredential(String walletId, String encryptedCredential, boolean isVerified, String issuerId, String credentialType) {
        CredentialMetadata credentialMetadata = new CredentialMetadata();
        credentialMetadata.setIsVerified(isVerified);
        credentialMetadata.setIssuerId(issuerId);
        credentialMetadata.setCredentialType(credentialType);

        VerifiableCredential verifiableCredential = new VerifiableCredential();
        verifiableCredential.setId(UUID.randomUUID().toString());
        verifiableCredential.setWalletId(walletId);
        verifiableCredential.setCredential(encryptedCredential);
        verifiableCredential.setCredentialMetadata(credentialMetadata);

        return walletCredentialsRepository.save(verifiableCredential);
    }

    private VerifiableCredentialResponseDTO buildCredentialResponseDTO(IssuerDTO issuerDTO, CredentialsSupportedResponse credentialsSupportedResponse,
                                                                       String locale, String credentialId) {
        String issuerName = "";
        String issuerLogo = "";
        String credentialType = "";
        String credentialTypeLogo = "";
        DisplayDTO issuerDisplayDTO;
        CredentialSupportedDisplayResponse credentialTypeDisplayDTO;

        if (issuerDTO != null) {
            issuerDisplayDTO = getIssuerDisplayDTOBasedOnLocale(issuerDTO.getDisplay(), locale);
            issuerName = issuerDisplayDTO.getName();
            issuerLogo = issuerDisplayDTO.getLogo().getUrl();
        }
        if (credentialsSupportedResponse != null) {
            credentialTypeDisplayDTO = getCredentialDisplayDTOBasedOnLocale(
                    credentialsSupportedResponse.getDisplay(), locale);
            credentialType = credentialTypeDisplayDTO.getName();
            credentialTypeLogo = credentialTypeDisplayDTO.getLogo().getUrl();
        }

        return VerifiableCredentialResponseDTO.builder()
                .issuerName(issuerName)
                .issuerLogo(issuerLogo)
                .credentialType(credentialType)
                .credentialTypeLogo(credentialTypeLogo)
                .credentialId(credentialId)
                .build();
    }
}
