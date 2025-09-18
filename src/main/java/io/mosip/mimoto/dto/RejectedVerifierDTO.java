package io.mosip.mimoto.dto;

import lombok.Data;

@Data
public class RejectedVerifierDTO {

    private String status;
    private String redirectUri;
    private String message;
}
