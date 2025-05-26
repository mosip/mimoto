package io.mosip.mimoto.dbentity;

import lombok.Data;

@Data
public class CredentialMetadata {
    private String issuerId;
    private String credentialType;
}