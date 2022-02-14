package io.mosip.residentapp.dto;

import lombok.Data;

@Data
public class CredentialDownloadRequestDTO {
    private String individualId;
    private String requestId;
}
