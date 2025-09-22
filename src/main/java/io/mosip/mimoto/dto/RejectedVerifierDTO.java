package io.mosip.mimoto.dto;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class RejectedVerifierDTO {

    private String status;
    private String redirectUri;
    private String message;
}
