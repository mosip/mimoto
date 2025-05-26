package io.mosip.mimoto.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
@Getter
@Setter
public class VerifiableCredentialRequestDTO {
    @Schema(description = "The unique identifier of the issuer")
    @NotBlank(message = "Missing required parameters: issuerId")
    String issuer;

    @Schema(description = "The unique identifier of the credential type from the issuer well-known configuration")
    @NotBlank(message = "Missing required parameters: credentialConfigurationId")
    String credentialConfigurationId;

    @Schema(description = "The authorization code received from the authorization server")
    String code;

    @Schema(description = "The grant type for the authorization request")
    String grantType;

    @Schema(description = "The redirect URI for the authorization request")
    String redirectUri;

    @Schema(description = "The code verifier used for PKCE (Proof Key for Code Exchange)")
    String codeVerifier;
}
