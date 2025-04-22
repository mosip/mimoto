package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class VerifiableCredentialResponseDTO {
    @JsonProperty("issuer_name")
    @Schema(description = "Name of the issuer")
    private String issuerName;

    @JsonProperty("issuer_logo")
    @Schema(description = "logo of the issuer")
    private String issuerLogo;

    @JsonProperty("credential_type")
    @Schema(description = "Name of the credential type")
    private String credentialType;

    @JsonProperty("credential_type_logo")
    @Schema(description = "logo of the credential type")
    private String credentialTypeLogo;

    @JsonProperty("credential_id")
    @Schema(description = "Unique Identifier of the Credential in database")
    private String credentialId;
}