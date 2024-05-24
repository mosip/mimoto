package io.mosip.mimoto.dto.mimoto;

import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
public class CredentialDefinitionResponseDto {
    private List<String> type;
    private Map<String, CredentialDisplayResponseDto> credentialSubject;
}
