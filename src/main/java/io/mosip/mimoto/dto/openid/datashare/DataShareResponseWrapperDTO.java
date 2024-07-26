package io.mosip.mimoto.dto.openid.datashare;

import io.mosip.mimoto.dto.ErrorDTO;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import javax.validation.constraints.NotNull;
import java.util.ArrayList;
import java.util.List;

@Data
@Builder
@AllArgsConstructor
public class DataShareResponseWrapperDTO {
    private String id;
    private String version;
    private String responsetime;
    @NotNull
    private DataShareResponseDTO dataShare;

    private List<ErrorDTO> errors = new ArrayList<>();
}
