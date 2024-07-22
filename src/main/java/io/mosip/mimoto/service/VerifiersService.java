package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.openid.VerifierDTO;
import io.mosip.mimoto.dto.openid.VerifiersDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationRequestDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;

import java.io.IOException;
import java.util.Optional;

public interface VerifiersService {
    Optional<VerifierDTO> getVerifiersByClientId(String clientId) throws ApiNotAccessibleException, IOException;
    void validateVerifier(PresentationRequestDTO presentationRequestDTO) throws ApiNotAccessibleException, IOException;
}
