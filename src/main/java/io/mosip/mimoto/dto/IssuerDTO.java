package io.mosip.mimoto.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.mosip.mimoto.model.QRCodeType;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;
import org.hibernate.validator.constraints.URL;
import java.util.List;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL;


@Data
public class IssuerDTO {
    @NotBlank
    @Schema(description = "Unique Identifier of the Issuer")
    String issuer_id;
    @NotBlank
    @Schema(description = "protocol of the download flow", allowableValues = {"OTP", "OpenId4VCI"})
    String protocol;
    @Valid
    @NotEmpty
    @Schema(description = "Display Properties of the Issuer")
    List<DisplayDTO> display;
    @NotBlank
    @Schema(description = "Client Id of the Onboarded Mimoto OIDC Client")
    String client_id;
    @URL
    @NotBlank
    @Schema(description = "Wellknown endpoint of the credential issuer")
    String wellknown_endpoint;
    @NotBlank
    @Schema(description = "Redirect URI configured while creating the OIDC Client")
    String redirect_uri;
    @NotBlank
    @Schema(description = "Authorization Audience for retrieving Token from token endpoint")
    String authorization_audience;
    @Schema(description = "Mimoto Token Endpoint Fetching the Token From Authorization Server with Client Assertion")
    String token_endpoint;
    @URL
    @NotBlank
    @Schema(description = "Token Endpoint for Fetching the Token From Authorization Server")
    String proxy_token_endpoint;
    @NotBlank
    @Schema(description = "Client Alias of the Issuer in the keyStore file")
    String client_alias;
    @Schema(description = "QR code type of issuer is used to decide whether the downloaded Verifiable Credential is allowed for online sharing or not")
    QRCodeType qr_code_type;
    @NotBlank
    @Schema(description = "Toggle to Enable / Disable the Issuer", defaultValue = "false")
    String enabled;
    @NotBlank
    @Schema(description = "Unique Identifier of the Issuer")
    String credential_issuer;
    @NotBlank
    @Schema(description = "Credential Issuer Host")
    String credential_issuer_host;
}
