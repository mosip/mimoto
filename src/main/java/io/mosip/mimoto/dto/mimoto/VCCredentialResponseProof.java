package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.validation.constraints.NotBlank;
import java.io.Serializable;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VCCredentialResponseProof implements Serializable {
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
