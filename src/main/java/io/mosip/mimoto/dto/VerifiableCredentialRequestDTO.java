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
    @NotBlank(message = "code cannot be blank")
    String code;

    @Schema(description = "The grant type for the authorization request")
    @NotBlank(message = "grantType cannot be blank")
    String grantType;

    @Schema(description = "The redirect URI for the authorization request")
    @NotBlank(message = "redirectUri cannot be blank")
    String redirectUri;

    @Schema(description = "The code verifier used for PKCE (Proof Key for Code Exchange)")
    @NotBlank(message = "codeVerifier cannot be blank")
    String codeVerifier;
}
