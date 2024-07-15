package io.mosip.mimoto.dto.openid;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;

@Data
public class VerifierDTO {
    @JsonProperty("client_id")
    String clientId;

    @JsonProperty("redirect_uri")
    List<String> redirectUri;
}
