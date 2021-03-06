package io.mosip.mimoto.dto.resident;

import java.util.List;

import lombok.Data;

@Data
public class AuthLockRequestDTO {
    private String transactionID;
    private String individualIdType = "UIN";
    private String individualId;
    private String otp;

    // Available: demo, bio-Finger, bio-Iris, bio-FACE
    private List<String> authType;
}
