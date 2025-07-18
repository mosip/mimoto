package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;


@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
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

    private String sdJwtVct;
}