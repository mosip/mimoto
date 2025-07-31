package io.mosip.mimoto.dto.openid.presentation;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ConstraintsDTO {
    FieldDTO[] fields;
    private String limitDisclosure;
}
