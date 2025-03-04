package io.mosip.mimoto.dto.mimoto;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
@AllArgsConstructor
public class CredentialIssuerConfiguration {
    private String credentialIssuer;

    private List<String> authorizationServers;

    private String credentialEndPoint;

    private Map<String, CredentialsSupportedResponse> credentialConfigurationsSupported;

    private AuthorizationServerWellKnownResponse authorizationServerWellKnownResponse;
}