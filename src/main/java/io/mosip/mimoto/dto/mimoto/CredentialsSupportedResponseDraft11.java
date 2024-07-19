package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.SerializedName;
import lombok.Data;

import java.util.List;
import java.util.Set;

@Data
public class CredentialsSupportedResponseDraft11 {
    private String format;
    private String id;
    private String scope;

    @SerializedName("proof_types_supported")
    @JsonProperty("proof_types_supported")
    private List<String> proofTypesSupported;

    @SerializedName("credential_definition")
    @JsonProperty("credential_definition")
    private CredentialDefinitionResponseDto credentialDefinition;

    private List<CredentialSupportedDisplayResponse> display;
    private Set<String> order;
}
