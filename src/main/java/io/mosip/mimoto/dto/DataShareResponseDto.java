package io.mosip.mimoto.dto;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DataShareResponseDto extends BaseRestResponseDTO {

    private static final long serialVersionUID = 1L;

    private DataShare dataShare;

    private List<ErrorDTO> errors;
}
