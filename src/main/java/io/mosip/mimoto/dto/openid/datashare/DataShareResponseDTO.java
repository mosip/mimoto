package io.mosip.mimoto.dto.openid.datashare;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class DataShareResponseDTO {
    private String url;
    private int validForInMinutes;
    private int transactionsAllowed;
    private String policyId;
    private String subscriberId;
}
