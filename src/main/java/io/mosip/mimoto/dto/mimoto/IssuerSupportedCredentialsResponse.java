package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;

@Data
public class IssuerSupportedCredentialsResponse {
    @JsonProperty("authorization_endpoint")
    private String authorizationEndPoint;
    private List<CredentialsSupportedResponse> supportedCredentials;
}
