package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
public class WalletBindingResponseDto {
    @Schema(description = "Certificate ID For Wallet Binding ")
    private String certificate;
    @Schema(description = "Encrypted Wallet Binding ID Received in the Binding OTP")
    private String encryptedWalletBindingId;
    @Schema(description = "Date Time of the Expiry")
    private String expireDateTime;
    @Schema(description = "Thumbprint Received in the Binding OTP")
    private String thumbprint;
    @Schema(description = "Key Id for Wallet Binding")
    private String keyId;
}
