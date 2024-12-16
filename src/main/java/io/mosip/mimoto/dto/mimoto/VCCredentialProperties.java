package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import java.util.List;
import java.util.Map;

@Data
@JsonPropertyOrder({"@context", "credentialSubject", "expirationDate", "id", "issuanceDate", "issuer", "proof", "type"})
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VCCredentialProperties {
    private String issuer;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String id;

    private String issuanceDate;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String expirationDate;

    private VCCredentialResponseProof proof;

    private Map<String, Object> credentialSubject;

    @JsonProperty("@context")
    private Object context;

    @NotEmpty
    private List<@NotBlank String> type;
}
