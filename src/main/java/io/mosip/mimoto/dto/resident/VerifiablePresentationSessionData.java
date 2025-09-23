package io.mosip.mimoto.dto.resident;

import io.mosip.mimoto.dto.DecryptedCredentialDTO;
import io.mosip.openID4VP.OpenID4VP;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.time.Instant;
import java.util.List;

@Data
@AllArgsConstructor
public class VerifiablePresentationSessionData {
    private OpenID4VP openID4VP;
    private Instant createdAt;
    private List<DecryptedCredentialDTO> matchingCredentials;
}
