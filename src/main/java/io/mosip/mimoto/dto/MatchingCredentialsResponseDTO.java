package io.mosip.mimoto.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MatchingCredentialsResponseDTO {

    @JsonProperty("availableCredentials")
    @Schema(description = "List of credentials that match the presentation definition")
    private List<SelectableCredentialDTO> availableCredentials;

    @JsonProperty("missingClaims")
    @Schema(description = "List of claims that are required but not available in any credential")
    private List<String> missingClaims;
}
