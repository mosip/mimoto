package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.SerializedName;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.hibernate.validator.constraints.URL;

import java.util.List;
import java.util.Map;

@Data
@AllArgsConstructor
public class CredentialIssuerConfigurationResponse {
    @NotBlank
    @URL
    @SerializedName("credential_issuer")
    @JsonProperty("credential_issuer")
    @Schema(description = "Unique Identifier of the Credential Issuer")
    private String credentialIssuer;

    @NotEmpty
    @SerializedName("authorization_servers")
    @JsonProperty("authorization_servers")
    @Schema(description = "List of Authorization Server Endpoint")
    private List<@NotBlank @URL String> authorizationServers;

    @NotBlank
    @SerializedName("credential_endpoint")
    @Pattern(regexp = "https?://.*?/credential$")
    @JsonProperty("credential_endpoint")
    @Schema(description = "Endpoint to download the Credential")
    private String credentialEndPoint;

    @NotEmpty
    @Valid
    @SerializedName("credential_configurations_supported")
    @JsonProperty("credential_configurations_supported")
    @Schema(description = "List of Credential Configurations Supported")
    private Map<@NotBlank String, @Valid CredentialsSupportedResponse> credentialConfigurationsSupported;

    @Valid
    @SerializedName("authorization")
    @JsonProperty("authorization")
    @Schema(description = "Authorization Server Configurations")
    private AuthorizationServerWellKnownResponse authorizationServerWellKnownResponse;
}


