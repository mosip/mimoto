package io.mosip.residentapp.dto;

import com.google.api.client.util.Key;


public class AttestationVerificationRequestDTO {
    public AttestationVerificationRequestDTO(String signedAttestation) {
        this.signedAttestation = signedAttestation;
    }

    @Key
    public String signedAttestation;
}