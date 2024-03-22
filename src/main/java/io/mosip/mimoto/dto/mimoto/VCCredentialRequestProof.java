package io.mosip.mimoto.dto.mimoto;

import lombok.Builder;
import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
@Builder
public class VCCredentialRequestProof {


    @NotBlank
    private String proof_type;

    private String jwt;

    private String cwt;
}
