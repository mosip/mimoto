package io.mosip.mimoto.dto.openid.presentation;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PresentationSubmissionDTO {
    String id;
    String definition_id;
    @JsonProperty("descriptor_map")
    List<SubmissionDescriptorDTO> descriptorMap;
}
