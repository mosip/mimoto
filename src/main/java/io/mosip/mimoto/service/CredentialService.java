package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.vercred.exception.ProofDocumentNotFoundException;
import io.mosip.vercred.exception.ProofTypeNotFoundException;
import io.mosip.vercred.exception.SignatureVerificationException;
import io.mosip.vercred.exception.UnknownException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Map;

public interface CredentialService {
    TokenResponseDTO getTokenResponse(Map<String, String> params, String issuerId) throws ApiNotAccessibleException, IOException;
    ByteArrayInputStream downloadCredentialAsPDF(String issuerId, String credentialType, TokenResponseDTO response) throws Exception;
    Boolean verifyCredential(String credential) throws ProofDocumentNotFoundException, ProofTypeNotFoundException, SignatureVerificationException, UnknownException;
}
