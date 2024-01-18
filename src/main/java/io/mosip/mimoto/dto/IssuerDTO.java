package io.mosip.mimoto.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import lombok.Data;
import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import java.util.List;
import java.util.Map;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.*;


@Data
public class IssuerDTO {
    @Expose
    @NotBlank
    String credential_issuer;
    @Expose
    @NotBlank
    String protocol;
    @Expose
    @Valid
    @NotEmpty
    List<DisplayDTO> display;
    @Expose
    @NotBlank
    String client_id;
    @SerializedName(".well-known")
    @JsonProperty(".well-known")
    @Expose
    String wellKnownEndpoint;
    @JsonInclude(NON_NULL)
    @NotBlank
    String redirect_uri;
    @JsonInclude(NON_NULL)
    @NotEmpty
    List<String> scopes_supported;
    @JsonInclude(NON_NULL)
    @NotBlank
    String authorization_endpoint;
    @JsonInclude(NON_NULL)
    @NotBlank
    String authorization_audience;
    @JsonInclude(NON_NULL)
    @NotBlank
    String token_endpoint;
    @JsonInclude(NON_NULL)
    @NotBlank
    String proxy_token_endpoint;
    @JsonInclude(NON_NULL)
    @NotBlank
    String credential_endpoint;
    @JsonInclude(NON_NULL)
    @NotEmpty
    List<String> credential_type;
    @JsonInclude(NON_NULL)
    @NotBlank
    String credential_audience;
    @JsonInclude(NON_NULL)
    @NotBlank
    String client_alias;
    @JsonInclude(NON_NULL)
    Map<String, String> additional_headers;
}
