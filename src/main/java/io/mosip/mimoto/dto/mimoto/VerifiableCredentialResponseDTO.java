package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor

// Holds details related to credential UUID as per stored in DB and other metadata to display in wallet
public class VerifiableCredentialResponseDTO {
    @Schema(description = "Name of the issuer")
    private String issuerDisplayName;

    @Schema(description = "logo of the issuer")
    private String issuerLogo;

    @Schema(description = "Name of the credential type")
    private String credentialTypeDisplayName;

    @Schema(description = "logo of the credential type")
    private String credentialTypeLogo;

    @Schema(description = "Unique Identifier of the Credential in database")
    private String credentialId;
}