package io.mosip.mimoto.dto.openid.presentation;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import java.util.List;

@Data
public class PresentationSubmissionDTO {
    String id;
    String definition_id;
    @JsonProperty("descriptor_map")
    List<SubmissionDescriptorDTO> descriptorMap;
}
