package io.mosip.mimoto.dto;

import io.mosip.mimoto.model.WalletStatus;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;


@Data
@AllArgsConstructor
@Builder
public class GetWalletResponseDto {
    @Schema(description = "Unique identifier of the Wallet")
    String walletId;
    @Schema(description = "Wallet name provided by user")
    String walletName;
    @Schema(description = "Wallet status indicating if it is locked or unlocked")
    WalletStatus walletStatus;
}
