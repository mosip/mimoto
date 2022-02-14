package io.mosip.residentapp.dto.mosip.resident;

import lombok.Data;

@Data
public class OTPResponseMaskedDTO {

    private String maskedMobile;
    private String maskedEmail;

}
