package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

import jakarta.validation.constraints.NotBlank;

@Data
@Builder
public class VCCredentialRequestProof {

    @JsonProperty("proof_type")
    @NotBlank
    private String proofType;

    private String jwt;

    private String cwt;
}
