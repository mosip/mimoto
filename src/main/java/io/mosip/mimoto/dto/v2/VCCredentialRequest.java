package io.mosip.mimoto.dto.v2;

import lombok.Builder;
import lombok.Data;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;


@Data
@Builder
public class VCCredentialRequest {

    @NotBlank
    private String format;

    @Valid
    @NotNull
    private VCCredentialRequestProof proof;

    @Valid
    @NotNull
    private VCCredentialDefinition credential_definition;
}