package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.SerializedName;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
public class CredentialIssuerWellKnownResponse {
    @SerializedName("credential_issuer")
    @JsonProperty("credential_issuer")
    private String credentialIssuer;

    @SerializedName("authorization_servers")
    @JsonProperty("authorization_servers")
    private List<String> authorizationServers;

    @SerializedName("credential_endpoint")
    @JsonProperty("credential_endpoint")
    private String credentialEndPoint;

    @SerializedName("credential_configurations_supported")
    @JsonProperty("credential_configurations_supported")
    private Map<String,CredentialsSupportedResponse> credentialConfigurationsSupported;
}
