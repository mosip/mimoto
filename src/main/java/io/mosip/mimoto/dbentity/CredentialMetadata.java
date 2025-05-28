package io.mosip.mimoto.dbentity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class CredentialMetadata {
    private String issuerId;
    private String credentialType;
}