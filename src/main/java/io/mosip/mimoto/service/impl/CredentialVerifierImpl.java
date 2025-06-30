package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;
import io.mosip.mimoto.exception.VCVerificationException;
import io.mosip.mimoto.service.CredentialVerifierService;
import io.mosip.vercred.vcverifier.CredentialsVerifier;
import io.mosip.vercred.vcverifier.constants.CredentialFormat;
import io.mosip.vercred.vcverifier.data.VerificationResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class CredentialVerifierImpl implements CredentialVerifierService {

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private CredentialsVerifier credentialsVerifier;

    public boolean verify(VCCredentialResponse response) throws JsonProcessingException, VCVerificationException {
        String credentialString = objectMapper.writeValueAsString(response.getCredential());
        VerificationResult result = credentialsVerifier.verify(credentialString, CredentialFormat.LDP_VC);
        if (!result.getVerificationStatus()) {
            throw new VCVerificationException(result.getVerificationErrorCode().toLowerCase(), result.getVerificationMessage());
        }
        return true;
    }
}
