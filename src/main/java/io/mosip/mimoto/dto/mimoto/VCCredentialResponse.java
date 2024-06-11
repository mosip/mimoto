package io.mosip.mimoto.dto.mimoto;

import lombok.Data;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

@Data
public class VCCredentialResponse {

    @NotBlank
    private String format;

    @Valid
    @NotNull
    private VCCredentialProperties credential;
}
