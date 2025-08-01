package io.mosip.mimoto.core.http;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

import io.mosip.mimoto.dto.ErrorDTO;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@NoArgsConstructor
public class ResponseWrapper<T> {
    @NotNull
    @Valid
    private T response;
    private List<ErrorDTO> errors = new ArrayList<>();
}
