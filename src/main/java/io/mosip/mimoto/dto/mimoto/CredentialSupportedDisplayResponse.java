package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import io.mosip.mimoto.dto.LogoDTO;
import lombok.Data;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import java.util.Map;

@Data
public class CredentialSupportedDisplayResponse {

    @Expose
    @NotBlank
    String name;

    @Expose
    @NotBlank
    String locale;

    @Expose
    @Valid
    LogoDTO logo;

    @JsonProperty("background_image")
    @SerializedName("background_image")
    @Expose
    @NotBlank
    Map <String,String> backgroundImage;

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
