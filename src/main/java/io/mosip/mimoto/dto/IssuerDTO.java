package io.mosip.mimoto.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import io.mosip.mimoto.model.QRCodeType;
import io.swagger.v3.oas.annotations.media.Schema;
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
    @Schema(description = "Unique Identifier of the Issuer")
    String credential_issuer;
    @Expose
    @NotBlank
    @Schema(description = "protocol of the download flow", allowableValues = {"OTP", "OpenId4VCI"})
    String protocol;
    @Expose
    @Valid
    @NotEmpty
    @Schema(description = "Display Properties of the Issuer")
    List<DisplayDTO> display;
    @Expose
    @NotBlank
    @Schema(description = "Client Id of the Onboarded Mimoto OIDC Client")
    String client_id;
    @NotBlank
    @Expose
    @Schema(description = "Wellknown endpoint of the credential issuer")
    String wellknown_endpoint;
    @Expose
    @JsonInclude(NON_NULL)
    @NotBlank
    @Schema(description = "Redirect URI configured while creating the OIDC Client")
    String redirect_uri;
    @JsonInclude(NON_NULL)
    @NotBlank
    @Schema(description = "Authorization Audience for retrieving Token from token endpoint")
    String authorization_audience;
    @Expose
    @JsonInclude(NON_NULL)
    @Schema(description = "Mimoto Token Endpoint Fetching the Token From Authorization Server with Client Assertion")
    String token_endpoint;
    @Expose
    @JsonInclude(NON_NULL)
    @NotBlank
    @Schema(description = "Token Endpoint for Fetching the Token From Authorization Server")
    String proxy_token_endpoint;
    @Expose
    @JsonInclude(NON_NULL)
    @NotBlank
    @Schema(description = "Client Alias of the Issuer in the keyStore file")
    String client_alias;
    QRCodeType qr_code_type;
    @Expose
    @JsonInclude(NON_NULL)
    @NotBlank
    @Schema(description = "Toggler to Enable / Disable the Issuer", defaultValue = "false")
    String enabled;
}
