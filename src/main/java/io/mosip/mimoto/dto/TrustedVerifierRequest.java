package io.mosip.mimoto.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class TrustedVerifierRequest {
    @NotBlank(message = "verifierId is required")
    @Size(max = 255, message = "verifierId must not exceed 255 characters")
    private String verifierId;
}
