package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.SerializedName;
import lombok.Data;

@Data
public class CredentialIssuerDisplayResponse {

    @SerializedName("name")
    @JsonProperty("name")
    private String name;

    @SerializedName("locale")
    @JsonProperty("locale")
    private String locale;
}
