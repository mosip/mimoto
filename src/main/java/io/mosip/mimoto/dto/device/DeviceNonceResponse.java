package io.mosip.mimoto.dto.device;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Single-use nonce for device registration or a device proof")
public record DeviceNonceResponse(
        @Schema(description = "Nonce to bind into the attestation or device proof") String nonce,
        @JsonProperty("expires_in") @Schema(description = "Seconds until the nonce expires") long expiresIn) {
}
