package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.openid.VerifierDTO;
import io.mosip.mimoto.dto.openid.VerifiersDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.InvalidVerifierException;
import io.mosip.mimoto.service.VerifierService;
import io.mosip.mimoto.util.Utilities;
import org.apache.commons.validator.routines.UrlValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;

import java.util.Optional;

import static org.apache.commons.validator.routines.UrlValidator.ALLOW_ALL_SCHEMES;
import static org.apache.commons.validator.routines.UrlValidator.ALLOW_LOCAL_URLS;


@Service
public class VerifierServiceImpl implements VerifierService {

    @Autowired
    Utilities utilities;

    @Autowired
    ObjectMapper objectMapper;

    private static final PathMatcher pathMatcher;
    private static final UrlValidator urlValidator;

    static {
        pathMatcher = new AntPathMatcher();
        urlValidator = new UrlValidator(ALLOW_ALL_SCHEMES+ALLOW_LOCAL_URLS);
    }

    private final Logger logger = LoggerFactory.getLogger(VerifierServiceImpl.class);

    public Optional<VerifierDTO> getVerifierByClientId(String clientId) throws ApiNotAccessibleException, JsonProcessingException {
        String trustedVerifiersJsonValue = utilities.getTrustedVerifiersJsonValue();
        if (trustedVerifiersJsonValue == null) {
            throw new ApiNotAccessibleException();
        }
        VerifiersDTO verifiersDTO = objectMapper.readValue(trustedVerifiersJsonValue, VerifiersDTO.class);
        return verifiersDTO.getVerifiers().stream().filter(verifier -> verifier.getClientId().equals(clientId)).findFirst();
    }
    @Override
    public void validateVerifier(String clientId, String redirectUri) throws ApiNotAccessibleException, JsonProcessingException {
        logger.info("Started the presentation Validation");
        getVerifierByClientId(clientId).ifPresentOrElse(
            (verifierDTO) -> {
                boolean isValidVerifier = verifierDTO.getRedirectUri().stream().anyMatch(registeredRedirectUri ->
                        urlValidator.isValid(registeredRedirectUri) &&
                        urlValidator.isValid(redirectUri) &&
                        pathMatcher.match(registeredRedirectUri, redirectUri));
                if(!isValidVerifier){
                    throw new InvalidVerifierException(
                            ErrorConstants.INVALID_REDIRECT_URI.getErrorCode(),
                            ErrorConstants.INVALID_REDIRECT_URI.getErrorMessage());
                }
            },
            () -> {
                throw new InvalidVerifierException(
                        ErrorConstants.INVALID_CLIENT.getErrorCode(),
                        ErrorConstants.INVALID_CLIENT.getErrorMessage());
            }
        );
    }
}
