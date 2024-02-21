package io.mosip.mimoto.dto.v2;

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
    private VCCredentialIssueBody credential;
}
