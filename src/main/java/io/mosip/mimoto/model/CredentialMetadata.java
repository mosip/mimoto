package io.mosip.mimoto.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

import java.io.Serializable;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class CredentialMetadata implements Serializable {
    private String issuerId;
    private String credentialType;
}