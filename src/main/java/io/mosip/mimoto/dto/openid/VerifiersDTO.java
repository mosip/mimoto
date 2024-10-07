package io.mosip.mimoto.dto.openid;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VerifiersDTO {
    @Schema(description = "Trusted Verifiers List")
    List<VerifierDTO> verifiers;
}
