package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.SerializedName;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
public class CredentialDefinitionResponseDto {

    @NotEmpty
    @SerializedName("type")
    @JsonProperty("type")
    private List<@NotEmpty String> type;

    @NotEmpty
    @Valid
    @SerializedName("credentialSubject")
    @JsonProperty("credentialSubject")
    private Map<@NotEmpty String, @Valid CredentialDisplayResponseDto> credentialSubject;
}
