package io.mosip.mimoto.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RejectedVerifierErrorDTO {

    private String status;
    private String message;
}
