package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
public class IdpChallangeDto {
    @Schema(description = "Auth Factory type", allowableValues = {"OTP"})
    private String authFactorType;
    @Schema(description = "IDP Challenge")
    private String challenge;
    @Schema(description = "IDP Format", allowableValues = {"jwt"})
    private String format;
}
