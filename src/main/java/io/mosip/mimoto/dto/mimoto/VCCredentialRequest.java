package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;


@Data
@Builder
public class VCCredentialRequest {

    @NotBlank
    private String format;

    @Valid
    @NotNull
    private VCCredentialRequestProof proof;

    @JsonProperty("credential_definition")
    @Valid
    @NotNull
    private VCCredentialDefinition credentialDefinition;
}