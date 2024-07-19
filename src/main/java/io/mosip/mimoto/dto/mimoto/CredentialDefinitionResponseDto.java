package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.SerializedName;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
public class CredentialDefinitionResponseDto {
    @SerializedName("type")
    @JsonProperty("type")
    private List<String> type;

    @SerializedName("credentialSubject")
    @JsonProperty("credentialSubject")
    private Map<String, CredentialDisplayResponseDto> credentialSubject;
}
