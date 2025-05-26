package io.mosip.mimoto.dto;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
@Getter
@Setter
public class VerifiableCredentialRequestDTO {
    //TODO: Add schema definition
    String issuer;
    String credentialConfigurationId;
    String code;
    String grantType;
    String redirectUri;
    String codeVerifier;
}
