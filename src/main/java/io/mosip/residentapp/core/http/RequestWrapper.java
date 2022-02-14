package io.mosip.residentapp.core.http;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

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
