package io.mosip.mimoto.dto.mimoto;

import lombok.Data;

import java.util.List;

@Data
public class CredentialIssuerWellKnownResponse {
    private String credential_issuer;
    private String credential_endpoint;
    private List<CredentialsSupportedResponse> credentials_supported;
}
