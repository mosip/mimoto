package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.SerializedName;
import lombok.Data;

import java.util.List;
import java.util.Map;
import java.util.Set;

@Data
public class CredentialsSupportedResponse {
    private String format;
    private String scope;

    @SerializedName("proof_types_supported")
    @JsonProperty("proof_types_supported")
    private Map<String,ProofTypesSupported> proofTypesSupported;

    @SerializedName("credential_definition")
    @JsonProperty("credential_definition")
    private CredentialDefinitionResponseDto credentialDefinition;

    @SerializedName("display")
    @JsonProperty("display")
    private List<CredentialSupportedDisplayResponse> display;
    private Set<String> order;
}
