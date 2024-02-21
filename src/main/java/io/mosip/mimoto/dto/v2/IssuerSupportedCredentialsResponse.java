package io.mosip.mimoto.dto.v2;

import lombok.Data;

import java.util.List;

@Data
public class IssuerSupportedCredentialsResponse {
    private String authorization_endpoint;
    private List<CredentialsSupportedResponse> supportedCredentials;
}
