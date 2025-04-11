package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dbentity.VerifiableCredential;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.dto.resident.WalletCredentialResponseDTO;
import io.mosip.mimoto.repository.WalletCredentialsRepository;
import io.mosip.mimoto.service.WalletCredentialViewService;
import io.mosip.mimoto.util.CredentialUtilService;
import io.mosip.mimoto.util.EncryptionDecryptionUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.InputStreamResource;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.util.Optional;

import static io.mosip.mimoto.util.LocaleUtils.getCredentialDisplayDTOBasedOnLocale;

@Service
@Slf4j
public class WalletCredentialViewServiceImpl implements WalletCredentialViewService {

    @Autowired
    private WalletCredentialsRepository walletCredentialsRepository;

    @Autowired
    private EncryptionDecryptionUtil encryptionDecryptionUtil;

    @Autowired
    private IssuersServiceImpl issuersService;

    @Autowired
    private CredentialUtilService credentialUtilService;

    @Autowired
    private ObjectMapper objectMapper;

    @Override
    public WalletCredentialResponseDTO fetchVerifiableCredential(String credentialId, String base64EncodedWalletKey, String locale) throws Exception {
        Optional<VerifiableCredential> verifiableCredentialObj = walletCredentialsRepository.findById(credentialId);
        VerifiableCredential verifiableCredential;
        if (verifiableCredentialObj.isPresent()) {
            verifiableCredential = verifiableCredentialObj.get();
        } else {
            throw new RuntimeException("Credential not found");
        }

        String decryptCredentialResponse = encryptionDecryptionUtil.decryptCredential(verifiableCredential.getCredential(), base64EncodedWalletKey);
        String issuerId = verifiableCredential.getCredentialMetadata().getIssuerId();
        String credentialType = verifiableCredential.getCredentialMetadata().getCredentialType();
        String dataShareUrl = verifiableCredential.getCredentialMetadata().getDataShareUrl();
        String credentialValidity = verifiableCredential.getCredentialMetadata().getCredentialValidity();
        IssuerDTO issuerDTO = issuersService.getIssuerDetails(issuerId);
        CredentialIssuerConfiguration credentialIssuerConfiguration = issuersService.getIssuerConfiguration(issuerId);
        CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse = new CredentialIssuerWellKnownResponse(
                credentialIssuerConfiguration.getCredentialIssuer(),
                credentialIssuerConfiguration.getAuthorizationServers(),
                credentialIssuerConfiguration.getCredentialEndPoint(),
                credentialIssuerConfiguration.getCredentialConfigurationsSupported());
        CredentialsSupportedResponse credentialsSupportedResponse = credentialIssuerWellKnownResponse.getCredentialConfigurationsSupported().get(credentialType);
        
        VCCredentialResponse vcCredentialResponse = objectMapper.readValue(decryptCredentialResponse, VCCredentialResponse.class);
        ByteArrayInputStream byteArrayInputStream = credentialUtilService.generatePdfForVerifiableCredentials(credentialType, vcCredentialResponse, issuerDTO, credentialsSupportedResponse, dataShareUrl, credentialValidity, locale);
        String fileName = getCredentialDisplayDTOBasedOnLocale(credentialsSupportedResponse.getDisplay(), locale).getName();
        
        return new WalletCredentialResponseDTO(new InputStreamResource(byteArrayInputStream), fileName);
    }
}
