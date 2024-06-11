package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import io.mosip.mimoto.dto.LogoDTO;
import lombok.Data;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;

@Data
public class CredentialSupportedDisplayResponse {

    @Expose
    @NotBlank
    String name;

    @Expose
    @Valid
    LogoDTO logo;

    @Expose
    @NotBlank
    String locale;

    @JsonProperty("background_color")
    @SerializedName("background_color")
    @Expose
    @NotBlank
    String backgroundColor;

    @JsonProperty("text_color")
    @SerializedName("text_color")
    @Expose
    @NotBlank
    String textColor;
}
