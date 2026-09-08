package io.mosip.mimoto.dto;

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest;
import lombok.Getter;

@Getter
public class VPAuthorizationResult {
    private final VPResponseDTO responseDTO;
    private final AuthorizationRequest parsedAuthorizationRequest;

    public VPAuthorizationResult(VPResponseDTO responseDTO, AuthorizationRequest parsedAuthorizationRequest) {
        this.responseDTO = responseDTO;
        this.parsedAuthorizationRequest = parsedAuthorizationRequest;
    }
}