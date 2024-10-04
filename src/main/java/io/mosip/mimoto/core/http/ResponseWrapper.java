package io.mosip.mimoto.core.http;

import java.util.ArrayList;
import java.util.List;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import io.mosip.mimoto.dto.ErrorDTO;
import lombok.*;

@Data
@NoArgsConstructor
public class ResponseWrapper<T> {
    private T response;
    private List<ErrorDTO> errors = new ArrayList<>();

    public void setResponse(T response) {
        this.response = response;
        this.errors = null;
    }

    public void setErrors(List<ErrorDTO> errors) {
        this.errors = errors;
        this.response = null;
    }
}
