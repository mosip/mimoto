package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class CredentialDisplayResponse {

    @Schema(description = "Name of the Supported Credential")
    private String name;

    @Schema(description = "Locale of the Supported Credential")
    private String locale;

    @Schema(description = "Logo of the Supported Credential")
    private String logo;
}
