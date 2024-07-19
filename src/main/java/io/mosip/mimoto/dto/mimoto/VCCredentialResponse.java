package io.mosip.mimoto.dto.mimoto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VCCredentialResponse {

    @NotBlank
    private String format;

    @Valid
    @NotNull
    private VCCredentialProperties credential;
}
