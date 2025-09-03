package io.mosip.mimoto.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class VerifiablePresentationVerifierDTO {

    @Schema(description = "Unique identifier (client_id) of the Verifier")
    private String id;

    @Schema(description = "Name of the Verifier")
    private String name;

    @Schema(description = "Logo URL of the Verifier")
    private String logo;

    @Schema(description = "Indicates if the Verifier is trusted by the User through the wallet")
    private boolean isTrusted;

    @Schema(description = "Indicates if the Verifier is pre-registered with the wallet")
    private boolean isPreregisteredWithWallet;

    @Schema(description = "Redirect URI used to redirect the User back to the Verifier after the presentation is completed")
    private String redirectUri;
}