package io.mosip.mimoto.dto;

import java.util.List;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class DataShareResponseDto extends BaseRestResponseDTO {

    private static final long serialVersionUID = 1L;

    private DataShare dataShare;

    private List<ErrorDTO> errors;
}
