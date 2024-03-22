package io.mosip.mimoto.dto.mimoto;

import lombok.Data;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

@Data
public class VCCredentialResponse {

    @NotBlank
    private String format;

    @Valid
    @NotNull
    private VCCredentialProperties credential;
}
