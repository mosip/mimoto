package io.mosip.mimoto.dto.mimoto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VerifiableCredentialResponse {

    @Valid
    @NotNull
    private Object credential;
}
