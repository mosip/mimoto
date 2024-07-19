package io.mosip.mimoto.dto.openid;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VerifiersDTO {
    List<VerifierDTO> verifiers;
}
