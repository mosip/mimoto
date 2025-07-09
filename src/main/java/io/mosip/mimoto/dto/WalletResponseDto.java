package io.mosip.mimoto.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@AllArgsConstructor
@Builder
public class WalletResponseDto {
    @Schema(description = "Unique identifier of the Wallet")
    String walletId;
    @Schema(description = "Wallet name provided by user")
    String walletName;
    @JsonIgnore
    @Schema(hidden = true)
    String decryptedWalletKey;
}
