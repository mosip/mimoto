package io.mosip.mimoto.dto;

import com.google.gson.annotations.Expose;
import lombok.Data;

import jakarta.validation.Valid;
import java.util.List;

@Data
public class IssuersDTO {

    @Expose
    @Valid
    List<IssuerDTO> issuers;

}
