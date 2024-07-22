package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.SerializedName;
import lombok.Data;

import java.util.List;

@Data
public class CredentialDisplayResponseDto {

    @SerializedName("display")
    @JsonProperty("display")
    private List<CredentialIssuerDisplayResponse> display;
}
