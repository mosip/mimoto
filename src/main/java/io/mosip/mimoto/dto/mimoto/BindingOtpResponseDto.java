package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
public class BindingOtpResponseDto {
    @Schema(description = "Transaction Id of Binding OTP")
    private String transactionId;
    @Schema(description = "Masked Email of Binding OTP")
    private String maskedEmail;
    @Schema(description = "Masked Mobile Number of Binding OTP")
    private String maskedMobile;
}
