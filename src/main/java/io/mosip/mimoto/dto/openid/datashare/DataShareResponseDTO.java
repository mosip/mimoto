package io.mosip.mimoto.dto.openid.datashare;

import lombok.Data;

@Data
public class DataShareResponseDTO {
    private String url;
    private int validForInMinutes;
    private int transactionsAllowed;
    private String policyId;
    private String subscriberId;
}
