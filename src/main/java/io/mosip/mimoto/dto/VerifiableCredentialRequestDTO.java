package io.mosip.mimoto.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class VerifiableCredentialRequestDTO {
    @Schema(description = "The unique identifier of the issuer")
    @NotBlank(message = "issuerId cannot be blank")
    String issuer;

    @Schema(description = "The unique identifier of the credential type from the issuer well-known configuration")
    @NotBlank(message = "credentialConfigurationId cannot be blank")
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
