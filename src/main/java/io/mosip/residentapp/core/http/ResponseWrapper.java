package io.mosip.residentapp.core.http;

import java.util.ArrayList;
import java.util.List;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import io.mosip.residentapp.dto.mosip.ErrorDTO;
import lombok.Data;

@Data
public class ResponseWrapper<T> {
    private String id;
    private String version;
    String str;
    private String responsetime;
    private Object metadata;
    @NotNull
    @Valid
    private T response;

    private List<ErrorDTO> errors = new ArrayList<>();

}
