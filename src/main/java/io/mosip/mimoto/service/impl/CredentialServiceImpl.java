package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.model.QRCodeType;
import io.mosip.mimoto.service.CredentialService;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.util.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.io.ByteArrayInputStream;
import static io.mosip.mimoto.exception.ErrorConstants.*;

@Slf4j
@Service
public class CredentialServiceImpl implements CredentialService {

    @Autowired
    IssuersService issuersService;

    @Autowired
    DataShareServiceImpl dataShareService;

    @Autowired
    ObjectMapper objectMapper;

    @Autowired
    private CredentialUtilService credentialUtilService;


    @Override
    public ByteArrayInputStream downloadCredentialAsPDF(String issuerId, String credentialType, TokenResponseDTO response, String credentialValidity, String locale) throws Exception {
        IssuerDTO issuerDTO = issuersService.getIssuerDetails(issuerId);
        CredentialIssuerConfiguration credentialIssuerConfiguration = issuersService.getIssuerConfiguration(issuerId);
        CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse = new CredentialIssuerWellKnownResponse(
                credentialIssuerConfiguration.getCredentialIssuer(),
                credentialIssuerConfiguration.getAuthorizationServers(),
                credentialIssuerConfiguration.getCredentialEndPoint(),
                credentialIssuerConfiguration.getCredentialConfigurationsSupported());
        CredentialsSupportedResponse credentialsSupportedResponse = credentialIssuerWellKnownResponse.getCredentialConfigurationsSupported().get(credentialType);
        VCCredentialRequest vcCredentialRequest = credentialUtilService.generateVCCredentialRequest(issuerDTO, credentialIssuerWellKnownResponse, credentialsSupportedResponse, response.getAccess_token(), null, null, false
        );
        VCCredentialResponse vcCredentialResponse = credentialUtilService.downloadCredential(credentialIssuerWellKnownResponse.getCredentialEndPoint(), vcCredentialRequest, response.getAccess_token());
        boolean verificationStatus = issuerId.toLowerCase().contains("mock") || credentialUtilService.verifyCredential(vcCredentialResponse);
        if (verificationStatus) {
            String dataShareUrl = QRCodeType.OnlineSharing.equals(issuerDTO.getQr_code_type()) ? dataShareService.storeDataInDataShare(objectMapper.writeValueAsString(vcCredentialResponse), credentialValidity) : "";
            return credentialUtilService.generatePdfForVerifiableCredentials(credentialType, vcCredentialResponse, issuerDTO, credentialsSupportedResponse, dataShareUrl, credentialValidity, locale);
        }
        throw new VCVerificationException(SIGNATURE_VERIFICATION_EXCEPTION.getErrorCode(),
                SIGNATURE_VERIFICATION_EXCEPTION.getErrorMessage());
    }
}
