package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.SerializedName;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import lombok.Data;
import org.hibernate.validator.constraints.URL;

import java.util.List;
import java.util.Map;

@Data
public class CredentialIssuerWellKnownResponse {
    @NotBlank
    @URL
    @SerializedName("credential_issuer")
    @JsonProperty("credential_issuer")
    private String credentialIssuer;

    @NotEmpty
    @SerializedName("authorization_servers")
    @JsonProperty("authorization_servers")
    private List<@NotBlank @URL String> authorizationServers;

    @NotBlank
    @SerializedName("credential_endpoint")
    @Pattern(regexp = "https?://.*?/credential$")
    @JsonProperty("credential_endpoint")
    private String credentialEndPoint;

    @NotEmpty
    @Valid
    @SerializedName("credential_configurations_supported")
    @JsonProperty("credential_configurations_supported")
    private Map<@NotBlank String, @Valid CredentialsSupportedResponse> credentialConfigurationsSupported;
}
