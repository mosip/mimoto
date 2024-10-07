package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class WalletBindingInternalRequestDTO {
    @Schema(description = "Request Time of the Wallet Binding")
    private String requestTime;
    @Schema(description = "Body of the Request")
    private WalletBindingInnerRequestDto request;

}
