package io.mosip.mimoto.dto.mimoto;

import lombok.Data;

import java.util.List;

@Data
public class CredentialsSupportedResponse {
    private String format;
    private String id;
    private String scope;
    private List<String> proof_types_supported;
    private CredentialDefinitionResponseDto credential_definition;
    private List<CredentialSupportedDisplayResponse> display;
}
