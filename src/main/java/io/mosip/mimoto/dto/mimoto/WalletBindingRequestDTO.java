package io.mosip.mimoto.dto.mimoto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

@Data
public class WalletBindingRequestDTO {

    @Schema(description = "Request time of the wallet binding")
    private String requestTime;
    @Schema(description = "Request of the wallet binding")
    private WalletBindingInnerReq request;

}
