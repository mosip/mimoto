package io.mosip.residentapp.dto;

import com.google.api.client.util.Key;


public class AttestationVerificationResponseDTO {
    @Key
    public boolean isValidSignature;

    /**
     * Optional field that is only set when the server encountered an error processing the
     * request.
     */
    @Key
    public String error;
}