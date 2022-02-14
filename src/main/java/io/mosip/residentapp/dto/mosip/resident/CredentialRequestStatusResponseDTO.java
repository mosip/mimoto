package io.mosip.residentapp.dto.mosip.resident;

import lombok.Data;

@Data
public class CredentialRequestStatusResponseDTO {
    private String id;
    private String requestId;
    private String statusCode;
}
