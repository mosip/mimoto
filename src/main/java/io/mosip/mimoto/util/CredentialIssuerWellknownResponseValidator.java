package io.mosip.mimoto.util;

import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;

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
    }
}
