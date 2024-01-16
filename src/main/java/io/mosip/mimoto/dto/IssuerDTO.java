package io.mosip.mimoto.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import lombok.Data;

import java.util.List;
import java.util.Map;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.*;


@Data
public class IssuerDTO {
    @Expose
    String credential_issuer;
    @Expose
    List<DisplayDTO> display;
    @Expose
    String protocol;
    @Expose
    String client_id;
    @SerializedName(".well-known")
    @JsonProperty(".well-known")
    @Expose
    String wellKnownEndpoint;
    @JsonInclude(NON_NULL)
    String redirect_uri;
    @JsonInclude(NON_NULL)
    List<String> scopes_supported;
    @JsonInclude(NON_NULL)
    String authorization_endpoint;
    @JsonInclude(NON_NULL)
    String token_endpoint;
    @JsonInclude(NON_NULL)
    String credential_endpoint;
    @JsonInclude(NON_NULL)
    List<String> credential_type;
    @JsonInclude(NON_NULL)
    String credential_audience;
    @JsonInclude(NON_NULL)
    String client_alias;
    @JsonInclude(NON_NULL)
    Map<String, String> additional_headers;
}
