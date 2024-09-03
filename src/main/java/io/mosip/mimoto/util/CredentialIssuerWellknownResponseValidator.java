package io.mosip.mimoto.util;

import io.mosip.mimoto.dto.mimoto.CredentialDefinitionResponseDto;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.CredentialsSupportedResponse;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import org.apache.commons.lang.StringUtils;
import org.springframework.util.CollectionUtils;

import java.util.Set;

public class CredentialIssuerWellknownResponseValidator {
    public void validate(CredentialIssuerWellKnownResponse response, Validator validator) throws ApiNotAccessibleException, InvalidWellknownResponseException {
        Set<ConstraintViolation<CredentialIssuerWellKnownResponse>> violations = validator.validate(response);
        if (!violations.isEmpty()) {
            StringBuilder sb = new StringBuilder("Validation failed:");
            for (ConstraintViolation<CredentialIssuerWellKnownResponse> violation : violations) {
                sb.append("\n").append(violation.getPropertyPath()).append(": ").append(violation.getMessage());
            }
            throw new InvalidWellknownResponseException(sb.toString());
        }

        for (CredentialsSupportedResponse supportedCredentialConfiguration : response.getCredentialConfigurationsSupported().values()) {
            //TODO: Extract the vc specific validations to separate classes
            if (supportedCredentialConfiguration.getFormat().equals("mso_mdoc")) {
                if (StringUtils.isBlank(supportedCredentialConfiguration.getDoctype())) {
                    throw new InvalidWellknownResponseException("Mandatory field 'doctype' missing");
                }
                if (CollectionUtils.isEmpty(supportedCredentialConfiguration.getClaims())) {
                    throw new InvalidWellknownResponseException("Mandatory field 'claims' missing");
                }
            }

            if (supportedCredentialConfiguration.getFormat().equals("ldp_vc")) {
                if (supportedCredentialConfiguration.getCredentialDefinition() == null) {
                    throw new InvalidWellknownResponseException("credentialDefinition: must not be null");
                }
                Set<ConstraintViolation<CredentialDefinitionResponseDto>> credentialDefinitionViolations = validator.validate(supportedCredentialConfiguration.getCredentialDefinition());
                if (!credentialDefinitionViolations.isEmpty()) {
                    StringBuilder sb = new StringBuilder("Validation failed:");
                    for (ConstraintViolation<CredentialDefinitionResponseDto> violation : credentialDefinitionViolations) {
                        sb.append("\n").append(violation.getPropertyPath()).append(": ").append(violation.getMessage());
                    }
                    throw new InvalidWellknownResponseException(sb.toString());
                }
            }
        }
    }
}
