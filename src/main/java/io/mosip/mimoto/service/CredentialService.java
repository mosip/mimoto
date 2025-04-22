package io.mosip.mimoto.service;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import java.io.ByteArrayInputStream;

public interface CredentialService {
    ByteArrayInputStream downloadCredentialAsPDF(String issuerId, String credentialType, TokenResponseDTO response, String credentialValidity, String locale) throws Exception;
}
