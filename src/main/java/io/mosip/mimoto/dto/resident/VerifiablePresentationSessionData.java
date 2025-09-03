package io.mosip.mimoto.dto.resident;

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.time.Instant;

@Data
@AllArgsConstructor
public class VerifiablePresentationSessionData {
    private AuthorizationRequest authorizationRequest;
    private Instant createdAt;
}
