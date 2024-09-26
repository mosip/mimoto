package io.mosip.mimoto.dto;


import com.google.gson.annotations.Expose;
import lombok.Data;

import jakarta.validation.constraints.NotBlank;
import org.hibernate.validator.constraints.URL;

@Data
public class LogoDTO {
    @Expose
    @NotBlank
    @URL
    String url;
    @Expose
    @NotBlank
    String alt_text;
}
