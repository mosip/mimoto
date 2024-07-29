package io.mosip.mimoto.dto.openid.datashare;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class DataShareResponseDTO {
    private String url;
    private int validForInMinutes;
    private int transactionsAllowed;
    private String policyId;
    private String subscriberId;
}
