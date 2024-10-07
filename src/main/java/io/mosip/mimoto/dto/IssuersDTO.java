package io.mosip.mimoto.dto;

import com.google.gson.annotations.Expose;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Data;

import jakarta.validation.Valid;
import java.util.List;

@Data
public class IssuersDTO {

    @Expose
    @Valid
    @Schema(description = "List of Onboarded Issuers")
    List<IssuerDTO> issuers;

}
