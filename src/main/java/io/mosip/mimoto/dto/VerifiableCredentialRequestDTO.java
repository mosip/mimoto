package io.mosip.mimoto.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
@Getter
@Setter
public class VerifiableCredentialRequestDTO {
    //TODO: Add schema definition
    @NotBlank(message = "Missing required parameters: issuerId")
    String issuer;
    @NotBlank(message = "Missing required parameters: credentialConfigurationId")
    String credentialConfigurationId;
    String code;
    String grantType;
    String redirectUri;
    String codeVerifier;
}
