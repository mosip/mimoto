package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.SerializedName;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import java.util.Map;

@Data
@AllArgsConstructor
public class CredentialIssuerConfigurationDTO {
    @SerializedName("credential_configurations_supported")
    @JsonProperty("credential_configurations_supported")
    @Schema(description = "List of Credential types Supported and their configurations")
    private Map<String, CredentialsSupportedResponse> credentialConfigurationsSupported;

    @SerializedName("authorization")
    @JsonProperty("authorization")
    @Schema(description = "Authorization Server Configurations")
    private AuthorizationServerWellKnownResponse authorizationServerWellKnownResponse;
}
