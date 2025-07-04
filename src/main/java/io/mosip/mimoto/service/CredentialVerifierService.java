package io.mosip.mimoto.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.exception.VCVerificationException;

public interface CredentialVerifierService {
    boolean verify(VCCredentialResponse credentialResponse) throws JsonProcessingException, VCVerificationException;
}
