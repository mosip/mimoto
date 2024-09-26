package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.SerializedName;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.util.List;
import java.util.Map;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL;

@Data
public class CredentialsSupportedResponse {

    @NotBlank(message = "Format must not be blank")
    private String format;

    @NotBlank(message = "Scope must not be blank")
    private String scope;

    @JsonInclude(NON_NULL)
    private String doctype;

    @NotEmpty(message = "Proof types supported must not be empty")
    @Valid
    @SerializedName("proof_types_supported")
    @JsonProperty("proof_types_supported")
    private Map<@NotEmpty String, @Valid ProofTypesSupported> proofTypesSupported;

    @JsonInclude(NON_NULL)
    private Map<String, Object> claims;

    @SerializedName("credential_definition")
    @JsonProperty("credential_definition")
    @JsonInclude(NON_NULL)
    private CredentialDefinitionResponseDto credentialDefinition;

    @NotEmpty(message = "Display information must not be empty")
    @Valid
    @SerializedName("display")
    @JsonProperty("display")
    private List<@Valid CredentialSupportedDisplayResponse> display;

    private List<String> order;
}
