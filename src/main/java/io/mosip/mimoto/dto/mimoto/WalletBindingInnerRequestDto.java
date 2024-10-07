package io.mosip.mimoto.dto.mimoto;

import com.nimbusds.jose.jwk.JWK;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

import java.util.List;

@Data
public class WalletBindingInnerRequestDto {
    @Schema(description = "Individual Id of the Wallet Binding")
    private String individualId;
    @Schema(description = "Challenge List of the Wallet Binding")
    private List<IdpChallangeDto> challengeList;
    @Schema(description = "Public Key of the Wallet Binding in JWK")
    private JwkDto publicKey;
    @Schema(description = "Auth Factor Type of the Wallet Binding")
    private String authFactorType;
    @Schema(description = "Format of the Wallet Binding")
    private String format;
}
