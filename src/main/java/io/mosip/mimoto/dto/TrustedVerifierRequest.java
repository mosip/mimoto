package io.mosip.mimoto.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class TrustedVerifierRequest {
    @NotBlank(message = "verifierId is required")
    private String verifierId;
}
