package io.mosip.mimoto.dto;

import io.swagger.annotations.ApiModel;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;
import lombok.ToString;

@Data
@ToString
@ApiModel(description = "Model representing a user wallet request")
@Schema(description = "Wallet Request DTO", requiredProperties = {"walletPin"})
public class WalletRequestDto {
    @Schema(description = "Name of the Wallet")
    String walletPin;
    @Schema(description = "PIN used to unlock the Wallet")
    String walletName;
}
