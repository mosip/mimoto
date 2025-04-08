package io.mosip.mimoto.dbentity;

import lombok.Data;

@Data
public class CredentialMetadata {
    private Boolean isVerified;
    private String issuerId;
    private String credentialType;
}