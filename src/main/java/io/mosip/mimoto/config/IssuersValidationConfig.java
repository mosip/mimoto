package io.mosip.mimoto.config;

import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.AuthorizationServerWellknownResponseException;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import io.mosip.mimoto.service.IssuersService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

@Slf4j
@Component
public class IssuersValidationConfig implements ApplicationRunner {
    @Autowired
    IssuersService issuersService;

    @Autowired
    private Validator validator;

    private final String VALIDATION_ERROR_MSG = "\n\nValidation failed in Mimoto-issuers-config.json:";

    @Override
    public void run(ApplicationArguments args) throws ApiNotAccessibleException, IOException, AuthorizationServerWellknownResponseException, InvalidWellknownResponseException {
        log.info("Validation for mimoto-issuers-config.json STARTED");

        AtomicReference<Errors> errors = new AtomicReference<>();
        AtomicReference<String> fieldErrors = new AtomicReference<>("");
        AtomicReference<Set<String>> credentialIssuers = new AtomicReference<>(new HashSet<>());

        IssuersDTO issuerDTOList = null;
        try {
            issuerDTOList = issuersService.getAllIssuers();
        } catch (Exception e) {
            log.error(VALIDATION_ERROR_MSG , e);
            throw new RuntimeException(VALIDATION_ERROR_MSG);
        }

        if (issuerDTOList != null) {
            issuerDTOList.getIssuers().forEach(issuerDTO -> {
                if (!issuerDTO.getProtocol().equals("OTP")) {
                    errors.set(new BeanPropertyBindingResult(issuerDTO, "issuerDTO"));
                    validator.validate(issuerDTO, errors.get());
                    String issuerId = issuerDTO.getIssuer_id();
                    if (errors.get() != null && errors.get().hasErrors()) {
                        log.error("{} for issuer {}: {}", VALIDATION_ERROR_MSG, issuerId, errors.get());
                        errors.get().getFieldErrors().forEach(error -> {
                            fieldErrors.set(fieldErrors.get() + error.getField() + " " + error.getDefaultMessage() + "\n");
                        });
                        log.error(VALIDATION_ERROR_MSG + fieldErrors.get());
                        throw new RuntimeException(VALIDATION_ERROR_MSG);
                    }
                    String[] tokenEndpointArray = issuerDTO.getToken_endpoint().split("/");
                    Set<String> currentIssuers = credentialIssuers.get();
                    if (!currentIssuers.add(issuerId)) {
                        log.error(VALIDATION_ERROR_MSG + "duplicate value found " + issuerId);
                        throw new RuntimeException(VALIDATION_ERROR_MSG);
                    }
                    if (!tokenEndpointArray[tokenEndpointArray.length - 1].equals(issuerId)) {
                        log.error(VALIDATION_ERROR_MSG + "TokenEndpoint does not match with the credential issuer " + issuerId);
                        throw new RuntimeException(VALIDATION_ERROR_MSG);
                    }
                    credentialIssuers.set(currentIssuers);
                }
            });
        }

        log.info("Validation for mimoto-issuers-config.json COMPLETED");
    }
}