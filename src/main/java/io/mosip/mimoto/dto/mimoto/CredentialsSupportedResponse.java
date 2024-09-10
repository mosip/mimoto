package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.SerializedName;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
public class CredentialsSupportedResponse {

    @NotBlank(message = "Format must not be blank")
    private String format;

    @NotBlank(message = "Scope must not be blank")
    private String scope;

    @NotEmpty(message = "Proof types supported must not be empty")
    @Valid
    @SerializedName("proof_types_supported")
    @JsonProperty("proof_types_supported")
    private Map<@NotEmpty String, @Valid ProofTypesSupported> proofTypesSupported;

    @Valid
    @NotNull
    @SerializedName("credential_definition")
    @JsonProperty("credential_definition")
    private CredentialDefinitionResponseDto credentialDefinition;

    @NotEmpty(message = "Display information must not be empty")
    @Valid
    @SerializedName("display")
    @JsonProperty("display")
    private List<@Valid CredentialSupportedDisplayResponse> display;

    private List<String> order;
}
