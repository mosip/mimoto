package io.mosip.mimoto.dto.mimoto;

import lombok.Data;

import java.util.List;

@Data
public class IssuerSupportedCredentialsResponse {
    private String authorization_endpoint;
    private List<CredentialsSupportedResponse> supportedCredentials;
}
