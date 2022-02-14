package io.mosip.residentapp.dto.mosip.resident;

import java.util.List;

import lombok.Data;

@Data
public class AuthUnlockRequestDTO {
    private String transactionID;
    private String individualIdType = "UIN";
    private String individualId;
    private String otp;

    // Available: demo, bio-Finger, bio-Iris, bio-FACE
    private List<String> authType;

    private String unlockForSeconds = "0";
}
