package io.mosip.mimoto.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for the response when a presentation is successfully submitted
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Response payload for successful presentation submission")
public class SubmitPresentationResponseDTO {

    @Schema(description = "Unique identifier of the submitted presentation", 
            example = "presentation-123")
    private String presentationId;

    @Schema(description = "Status of the presentation submission", 
            example = "SUCCESS")
    private String status;

    @Schema(description = "Message indicating the result of the submission", 
            example = "Presentation successfully submitted and shared with verifier")
    private String message;
}
