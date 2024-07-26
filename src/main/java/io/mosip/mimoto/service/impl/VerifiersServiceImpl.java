package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.openid.VerifierDTO;
import io.mosip.mimoto.dto.openid.VerifiersDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationRequestDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.InvalidVerifierException;
import io.mosip.mimoto.exception.OpenIdErrorMessages;
import io.mosip.mimoto.exception.PlatformErrorMessages;
import io.mosip.mimoto.service.VerifiersService;
import io.mosip.mimoto.util.Utilities;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class VerifiersServiceImpl implements VerifiersService {

    @Autowired
    Utilities utilities;

    @Autowired
    ObjectMapper objectMapper;

    private final Logger logger = LoggerFactory.getLogger(VerifiersServiceImpl.class);

    @Override
    public Optional<VerifierDTO> getVerifiersByClientId(String clientId) throws ApiNotAccessibleException, JsonProcessingException {
        String trustedVerifiersJsonValue = utilities.getTrustedVerifiersJsonValue();
        if (trustedVerifiersJsonValue == null) {
            throw new ApiNotAccessibleException();
        }
        VerifiersDTO verifiersDTO = objectMapper.readValue(trustedVerifiersJsonValue, VerifiersDTO.class);
        return verifiersDTO.getVerifiers().stream().filter(verifier -> verifier.getClientId().equals(clientId)).findFirst();
    }
    @Override
    public void validateVerifier(PresentationRequestDTO presentationRequestDTO) throws ApiNotAccessibleException, JsonProcessingException {
        logger.info("Started the presentation Validation");
        getVerifiersByClientId(presentationRequestDTO.getClient_id()).ifPresentOrElse(
            (verifierDTO) -> {
                List<String> registeredRedirectUri = verifierDTO.getRedirectUri();
                if(!registeredRedirectUri.contains(presentationRequestDTO.getRedirect_uri())){
                    throw new InvalidVerifierException(
                            OpenIdErrorMessages.INVALID_REDIRECT_URI.getErrorCode(),
                            OpenIdErrorMessages.INVALID_REDIRECT_URI.getErrorMessage());
                }
            },
            () -> {
                throw new InvalidVerifierException(
                        OpenIdErrorMessages.INVALID_CLIENT.getErrorCode(),
                        OpenIdErrorMessages.INVALID_CLIENT.getErrorMessage());
            }
        );
    }
}
