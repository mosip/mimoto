package io.mosip.mimoto.core.http;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

import lombok.Data;

@Data
public class RequestWrapper<T> {
    private String id;
    private String version;

    private String requesttime;

    private Object metadata;

    @NotNull
    @Valid
    private T request;
}
