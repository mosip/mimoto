package io.mosip.mimoto.config;
import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.service.IssuersService;
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

@Component
public class OpenIdIssuerList implements ApplicationRunner {
    @Autowired
    IssuersService issuersService;

    @Autowired
    private Validator validator;

    private final String VALIDATION_ERROR_MSG = "\n\nValidation failed in Mimoto-issuers-config.json:";

    @Override
    public void run(ApplicationArguments args) throws ApiNotAccessibleException, IOException {
        IssuersDTO issuerDTOList = issuersService.getAllIssuersWithAllFields();

        AtomicReference<Errors> errors = new AtomicReference<>();
        AtomicReference<String> fieldErrors = new AtomicReference<>("");
        AtomicReference<Set<String>> credentialIssuers = new AtomicReference<>(new HashSet<>());

        if(issuerDTOList != null){
            issuerDTOList.getIssuers().forEach(issuerDTO -> {
                if (!issuerDTO.getProtocol().equals("OTP")) {
                    errors.set(new BeanPropertyBindingResult(issuerDTO, "issuerDTO"));
                    validator.validate(issuerDTO, errors.get());
                    String credentialIssuer = issuerDTO.getCredential_issuer();
                    String[] tokenEndpointArray = issuerDTO.getToken_endpoint().split("/");
                    Set<String> currentIssuers = credentialIssuers.get();
                    if (!currentIssuers.add(credentialIssuer)) {
                        throw new RuntimeException(VALIDATION_ERROR_MSG + "duplicate value found " + credentialIssuer);
                    }
                    if (!tokenEndpointArray[tokenEndpointArray.length - 1].equals(credentialIssuer)) {
                        throw new RuntimeException(VALIDATION_ERROR_MSG + "TokenEndpoint does not match with the credential issuer " + credentialIssuer);
                    }
                    credentialIssuers.set(currentIssuers);
                }
            });
        }


        if (errors.get() != null && errors.get().hasErrors()) {
            errors.get().getFieldErrors().forEach(error -> {
                fieldErrors.set(fieldErrors.get() + error.getField() + " " + error.getDefaultMessage() + "\n");
            });
            throw new RuntimeException(VALIDATION_ERROR_MSG + fieldErrors.get() );
        }
    }
}
