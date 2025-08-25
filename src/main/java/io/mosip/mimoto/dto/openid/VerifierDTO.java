package io.mosip.mimoto.dto.openid;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VerifierDTO {
    @JsonProperty("client_id")
    @Schema(description = "Client Id of the Verifier")
    String clientId;

    @JsonProperty("redirect_uris")
    @Schema(description = "Redirect URIs of the Verifier")
    List<String> redirectUris;

    @JsonProperty("response_uris")
    @Schema(description = "Response URIs of the Verifier")
    List<String> responseUris;

    @JsonProperty("client_metadata")
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @Schema(description = "Metadata of the Verifier")
    Map<String,?> clientMetadata;
}

