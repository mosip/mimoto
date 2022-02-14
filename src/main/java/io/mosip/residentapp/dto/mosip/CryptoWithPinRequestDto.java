/*
 * 
 * 
 * 
 * 
 */
package io.mosip.residentapp.dto.mosip;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Crypto-With-Pin-Request model
 * 
 * @author Mahammed Taheer
 *
 * @since 1.1.2
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@ApiModel(description = "Model representing a Crypto-With-Pin-Service Request")
public class CryptoWithPinRequestDto {

    /**
     * Data in String to encrypt/decrypt
     */

    @ApiModelProperty(notes = "Data in String to encrypt/decrypt", required = true)
    private String data;

    /**
     * Pin to be used for encrypt/decrypt
     */
    @ApiModelProperty(notes = " Pin to be used for encrypt/decrypt", required = true, example = "A1234")
    private String userPin;
}
