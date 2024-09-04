package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.SerializedName;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

import java.util.List;

@Data
public class CredentialDisplayResponseDto {

    @NotEmpty
    @Valid
    @SerializedName("display")
    @JsonProperty("display")
    private List<@Valid CredentialIssuerDisplayResponse> display;
}
