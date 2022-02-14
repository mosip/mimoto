package io.mosip.residentapp.dto.mosip.resident;

import java.util.List;
import java.util.Map;

import lombok.Data;

@Data
public class OTPRequestDTO {

    private String id;
    private String version;
    private String transactionID;
    private String requestTime;
    private String individualId;
    private String individualIdType;
    private List<String> otpChannel;
    private Map<String, Object> metadata;

}