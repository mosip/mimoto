package io.mosip.mimoto.dto.v2;

import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
public class CredentialDefinitionResponseDto {
    private List<String> type;
    private Map<String, CredentialDisplayResponseDto> credentialSubject;
}
