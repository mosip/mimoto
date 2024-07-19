package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

import jakarta.validation.constraints.NotBlank;

@Data
public class VCCredentialResponseProof {
    @NotBlank
    private String type;
    @NotBlank
    private String created;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String proofPurpose;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String verificationMethod;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String jws;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String proofValue;
}
