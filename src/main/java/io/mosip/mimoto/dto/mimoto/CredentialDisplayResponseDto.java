package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.SerializedName;
import io.swagger.v3.oas.annotations.media.Schema;
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
    @Schema(description = "Display Properties of the Credential Issuer")
    private List<@Valid CredentialIssuerDisplayResponse> display;
}
