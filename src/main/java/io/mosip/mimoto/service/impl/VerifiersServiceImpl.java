package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.openid.VerifierDTO;
import io.mosip.mimoto.dto.openid.VerifiersDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationRequestDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.InvalidVerifierException;
import io.mosip.mimoto.exception.PlatformErrorMessages;
import io.mosip.mimoto.service.VerifiersService;
import io.mosip.mimoto.util.Utilities;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

@Service
public class VerifiersServiceImpl implements VerifiersService {

    @Autowired
    Utilities utilities;

    @Autowired
    ObjectMapper objectMapper;

    @Override
    public Optional<VerifierDTO> getVerifiersByClientId(String clientId) throws ApiNotAccessibleException, IOException {
        String trustedVerifiersJsonValue = utilities.getTrustedVerifiersJsonValue();
        if (trustedVerifiersJsonValue == null) {
            throw new ApiNotAccessibleException();
        }
        VerifiersDTO verifiersDTO = objectMapper.readValue(trustedVerifiersJsonValue, VerifiersDTO.class);
        return verifiersDTO.getVerifiers().stream().filter(verifier -> verifier.getClientId().equals(clientId)).findFirst();
    }
    @Override
    public void validateVerifier(PresentationRequestDTO presentationRequestDTO) throws ApiNotAccessibleException, IOException {
        getVerifiersByClientId(presentationRequestDTO.getClient_id()).ifPresentOrElse(
            (verifierDTO) -> {
                List<String> registeredRedirectUri = verifierDTO.getRedirectUri();
                if(!registeredRedirectUri.contains(presentationRequestDTO.getRedirect_uri())){
                    throw new InvalidVerifierException(PlatformErrorMessages.INVALID_VERIFIER_REDIRECT_URI_EXCEPTION.getMessage());
                }
            },
            () -> {
                throw new InvalidVerifierException(PlatformErrorMessages.INVALID_VERIFIER_ID_EXCEPTION.getMessage());
            }
        );
    }
}
