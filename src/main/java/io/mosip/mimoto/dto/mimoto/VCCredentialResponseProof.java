package io.mosip.mimoto.dto.mimoto;

import lombok.Data;

import jakarta.validation.constraints.NotBlank;

@Data
public class VCCredentialResponseProof {
    @NotBlank
    private String type;
    @NotBlank
    private String created;
    @NotBlank
    private String proofPurpose;
    @NotBlank
    private String verificationMethod;
    @NotBlank
    private String jws;
}
