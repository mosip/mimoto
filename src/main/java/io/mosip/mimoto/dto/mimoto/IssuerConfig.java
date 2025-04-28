package io.mosip.mimoto.dto.mimoto;

import io.mosip.mimoto.dto.IssuerDTO;
import lombok.Data;

@Data
public class IssuerConfig {
    private final IssuerDTO issuerDTO;
    private final CredentialIssuerWellKnownResponse wellKnownResponse;
    private final CredentialsSupportedResponse credentialsSupportedResponse;
}
