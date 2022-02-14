package io.mosip.residentapp.dto;

import com.fasterxml.jackson.databind.JsonNode;

import lombok.Data;

@Data
public class CredentialDownloadResponseDTO {
    private JsonNode credential;
    private JsonNode verifiableCredential;
}
