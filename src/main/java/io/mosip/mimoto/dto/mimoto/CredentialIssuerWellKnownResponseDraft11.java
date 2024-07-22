package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.SerializedName;
import lombok.Data;

import java.util.List;

@Data
public class CredentialIssuerWellKnownResponseDraft11 {
    @SerializedName("credential_issuer")
    @JsonProperty("credential_issuer")
    private String credentialIssuer;

    @SerializedName("credential_endpoint")
    @JsonProperty("credential_endpoint")
    private String credentialEndPoint;

    @SerializedName("credentials_supported")
    @JsonProperty("credentials_supported")
    private List<CredentialsSupportedResponseDraft11> credentialsSupported;
}
