package io.mosip.mimoto.dto.mimoto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

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
