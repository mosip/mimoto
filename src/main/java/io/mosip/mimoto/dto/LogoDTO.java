package io.mosip.mimoto.dto;


import com.google.gson.annotations.Expose;
import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
public class LogoDTO {
    @Expose
    @NotBlank
    String url;
    @Expose
    @NotBlank
    String alt_text;
}
