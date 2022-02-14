package io.mosip.residentapp.dto.mosip;

import java.util.List;

import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = true)
public class DataShareResponseDto extends BaseRestResponseDTO {

    private static final long serialVersionUID = 1L;

    private DataShare dataShare;

    private List<ErrorDTO> errors;
}
