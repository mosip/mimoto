package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.SerializedName;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class CredentialIssuerDisplayResponse {

    @NotBlank
    @SerializedName("name")
    @JsonProperty("name")
    private String name;

    @NotBlank
    @SerializedName("locale")
    @JsonProperty("locale")
    private String locale;
}
