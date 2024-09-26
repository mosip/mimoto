package io.mosip.mimoto.dto;

import lombok.Data;

@Data
public class ServiceConfiguration {
    String authorizationEndpoint;
    String tokenEndpoint;
    String credentialEndpoint;
    String credentialAudience;
}
