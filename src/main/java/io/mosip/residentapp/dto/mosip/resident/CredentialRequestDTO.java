package io.mosip.residentapp.dto.mosip.resident;

import java.util.List;
import java.util.Map;

import lombok.Data;

@Data
public class CredentialRequestDTO {
    private String individualId;
    private String otp;
    private String transactionID;
    private String credentialType;
    private Boolean encrypt = false;
    private String encryptionKey;
    private String issuer;
    private String recepiant;
    private String user;
    private Map<String, Object> additionalData;
    private List<String> sharableAttributes;
}
