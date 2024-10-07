package io.mosip.mimoto.dto.openid.datashare;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class DataShareResponseDTO {

    @Schema(description = "url of the data share")
    private String url;

    @Schema(description = "The valid for in minutes.")
    private int validForInMinutes;

    @Schema(description = "The transactions allowed")
    private int transactionsAllowed;

    @Schema(description = "Static policy id")
    private String policyId;

    @Schema(description = "Static subscriber id")
    private String subscriberId;
}
