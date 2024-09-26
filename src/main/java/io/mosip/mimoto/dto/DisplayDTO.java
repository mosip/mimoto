package io.mosip.mimoto.dto;

import com.google.gson.annotations.Expose;
import lombok.Data;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;

@Data
public class DisplayDTO {
    @Expose
    @NotBlank
    String name;
    @Expose
    @Valid
    LogoDTO logo;
    @Expose
    @NotBlank
    String title;
    @Expose
    @NotBlank
    String description;
    @Expose
    @NotBlank
    String language;
}
