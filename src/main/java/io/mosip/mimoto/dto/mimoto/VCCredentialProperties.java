package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import java.util.List;
import java.util.Map;

@Data
public class VCCredentialProperties {
    private String issuer;

    private String id;

    private String issuanceDate;

    private VCCredentialResponseProof proof;

    private Map<String, Object> credentialSubject;

    @JsonProperty("@context")
    private Object context;

    @NotEmpty
    private List<@NotBlank String> type;
}
