package io.mosip.mimoto.dto.v2;

import com.google.gson.annotations.Expose;
import io.mosip.mimoto.dto.LogoDTO;
import lombok.Data;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;

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
    @Expose
    @NotBlank
    String background_color;
    @Expose
    @NotBlank
    String text_color;
}
