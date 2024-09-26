package io.mosip.mimoto.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.mosip.mimoto.dto.openid.VerifierDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationRequestDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;

import java.io.IOException;
import java.util.Optional;

public interface VerifierService {
    Optional<VerifierDTO> getVerifierByClientId(String clientId) throws ApiNotAccessibleException, IOException;
    void validateVerifier(String clientId, String redirectUri) throws ApiNotAccessibleException, JsonProcessingException;
}
