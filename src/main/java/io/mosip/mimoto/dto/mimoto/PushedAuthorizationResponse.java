package io.mosip.mimoto.dto.mimoto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class PushedAuthorizationResponse {

    @JsonProperty("request_uri")
    private String requestUri;

    @JsonProperty("expires_in")
    private Long expiresIn;
}
