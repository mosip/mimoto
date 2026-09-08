package io.mosip.mimoto.dto.resident;

import io.mosip.mimoto.dto.DecryptedCredentialDTO;
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class VerifiablePresentationSessionData implements Serializable {
    private String presentationId;
    private String authorizationRequest;
    private Instant createdAt;
    private boolean isVerifierClientPreregistered;
    private List<DecryptedCredentialDTO> matchingCredentials;
    /** True when the authorization request had a DCQL query; selects DCQL vs PE flow. */
    private boolean dcql;
    /** Parsed result of the initial authenticateVerifier call — stored to avoid re-authentication.
     *  Transient: not serialized (in-memory session only). Falls back to raw authorizationRequest string if null. */
    private transient AuthorizationRequest parsedAuthorizationRequest;
}
