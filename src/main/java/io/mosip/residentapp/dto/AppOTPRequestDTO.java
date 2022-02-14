package io.mosip.residentapp.dto;

import java.util.List;
import lombok.Data;

@Data
public class AppOTPRequestDTO {
    private String individualId;
    private String individualIdType;
    private List<String> otpChannel;
    private String transactionID;
}