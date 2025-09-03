package io.mosip.mimoto.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class VerifiablePresentationResponseDTO {

    @Schema(description = "Unique identifier for the Verifiable Presentation")
    String presentationId;

    @Schema(description = "Information about the Verifier who sent the Verifiable Presentation request")
    VerifiablePresentationVerifierDTO verifiablePresentationVerifierDTO;
}
