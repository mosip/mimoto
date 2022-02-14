package io.mosip.residentapp.dto;

import lombok.Data;

@Data
public class AppCredentialRequestDTO {
    private String individualId;
    private String otp;
    private String transactionID;
    private String issuer;
    private String credentialType;
}
