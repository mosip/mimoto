package io.mosip.mimoto.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import io.mosip.mimoto.model.QRCodeType;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.util.List;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL;


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
    @Expose
    @JsonInclude(NON_NULL)
    @NotBlank
    String redirect_uri;
    @JsonInclude(NON_NULL)
    @NotBlank
    String authorization_audience;
    @Expose
    @JsonInclude(NON_NULL)
    String token_endpoint;
    @Expose
    @JsonInclude(NON_NULL)
    @NotBlank
    String proxy_token_endpoint;
    @Expose
    @JsonInclude(NON_NULL)
    @NotBlank
    String client_alias;
    QRCodeType qr_code_type;
    @Expose
    @JsonInclude(NON_NULL)
    @NotBlank
    String enabled;
}
