package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
public class CredentialIssuerConfigurationResponseDTO {

    @JsonProperty("credentials_supported")
    @Schema(description = "List of Credential types Supported and their configurations")
    private List<CredentialsResponse> credentials;

    @JsonProperty("authorization_endpoint")
    @Schema(description = "Endpoint for Authenticating & Authorizing the user")
    private String authorizationEndpoint;

    @JsonProperty("grant_types_supported")
    @Schema(description = "List of grant types supported by Authorization Server")
    private List<String> grantTypesSupported;

}