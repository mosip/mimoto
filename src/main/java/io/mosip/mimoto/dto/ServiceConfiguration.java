package io.mosip.mimoto.dto;

import lombok.Data;

@Data
public class ServiceConfiguration {
    String authorizationEndpoint;
    String tokenEndpoint;
    String revocationEndpoint;
    String credentialEndpoint;
    String credentialAudience;
}