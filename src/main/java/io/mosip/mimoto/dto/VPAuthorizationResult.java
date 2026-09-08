package io.mosip.mimoto.dto;

import io.mosip.openID4VP.OpenID4VP;
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest;
import lombok.Getter;

@Getter
public class VPAuthorizationResult {
    private final VPResponseDTO responseDTO;
    private final AuthorizationRequest parsedAuthorizationRequest;
    private final OpenID4VP openID4VP;

    public VPAuthorizationResult(VPResponseDTO responseDTO, AuthorizationRequest parsedAuthorizationRequest, OpenID4VP openID4VP) {
        this.responseDTO = responseDTO;
        this.parsedAuthorizationRequest = parsedAuthorizationRequest;
        this.openID4VP = openID4VP;
    }
}