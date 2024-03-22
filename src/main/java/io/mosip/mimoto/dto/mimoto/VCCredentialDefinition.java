package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import java.util.List;
import java.util.Map;

@Data
@Builder
public class VCCredentialDefinition {

    @JsonProperty("@context")
    private List<@NotBlank String> context;

    @NotEmpty
    private List<@NotBlank String> type;

    private Map<String, Object> credentialSubject;

}
