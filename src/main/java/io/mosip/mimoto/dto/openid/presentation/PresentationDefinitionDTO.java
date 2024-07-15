package io.mosip.mimoto.dto.openid.presentation;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;

@Data
public class PresentationDefinitionDTO {

    String id;
    @JsonProperty("input_descriptors")
    List<InputDescriptorDTO> inputDescriptors;
}
