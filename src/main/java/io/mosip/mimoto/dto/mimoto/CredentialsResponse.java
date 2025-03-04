package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
public class CredentialsResponse {

    @Schema(description = "name of the Credential")
    private String name;

    @Schema(description = "Scope of the Credential")
    private String scope;

    @JsonProperty("display")
    @Schema(description = "Display Properties of the Supported Credential")
    private List<CredentialDisplayResponse> display;
}
