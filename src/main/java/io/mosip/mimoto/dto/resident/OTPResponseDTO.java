package io.mosip.mimoto.dto.resident;

import java.util.List;
import java.util.Map;

import io.mosip.mimoto.dto.ErrorDTO;
import lombok.Data;

@Data
public class OTPResponseDTO {

    private String id;

    private String version;

    private String transactionID;

    private String responseTime;

    private List<ErrorDTO> errors;

    private OTPResponseMaskedDTO response;

    private Map<String, Object> metadata;

}
