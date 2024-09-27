package io.mosip.mimoto.dto.openid;

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
public class VerifierDTO {
    @JsonProperty("client_id")
    String clientId;

    @JsonProperty("redirect_uris")
    List<String> redirectUris;

    @JsonProperty("response_uri")
    List<String> responseUri;
}
