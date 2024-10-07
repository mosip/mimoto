package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
public class WalletBindingInternalResponseDto {
    @Schema(description = "Certificate of the Wallet Binding")
    private String certificate;
    @Schema(description = "Wallet User Id of the Wallet Binding")
    private String walletUserId;
    @Schema(description = "Date Time Expiry of the Wallet Binding")
    private String expireDateTime;
}
