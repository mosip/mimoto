package io.mosip.mimoto.dto;

import io.swagger.annotations.ApiModel;
import lombok.Data;
import lombok.ToString;

@Data
@ToString
@ApiModel(description = "Model representing a user wallet request")
public class WalletRequestDto {
    String pin;
    String name;
}
