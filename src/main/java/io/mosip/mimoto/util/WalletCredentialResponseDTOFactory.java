package io.mosip.mimoto.util;

import io.mosip.mimoto.dto.DisplayDTO;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.mimoto.*;

import static io.mosip.mimoto.util.LocaleUtils.getCredentialDisplayDTOBasedOnLocale;
import static io.mosip.mimoto.util.LocaleUtils.getIssuerDisplayDTOBasedOnLocale;

public class WalletCredentialResponseDTOFactory {
    public static VerifiableCredentialResponseDTO buildCredentialResponseDTO(IssuerDTO issuerDTO, CredentialsSupportedResponse credentialsSupportedResponse,
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