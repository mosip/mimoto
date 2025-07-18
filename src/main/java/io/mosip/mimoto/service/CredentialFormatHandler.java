package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.mimoto.CredentialIssuerDisplayResponse;
import io.mosip.mimoto.dto.mimoto.CredentialsSupportedResponse;
import io.mosip.mimoto.dto.mimoto.VCCredentialRequest;
import io.mosip.mimoto.dto.mimoto.VCCredentialResponse;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public interface CredentialFormatHandler {
    /**
     * Extract credential subject properties from VC response
     */
    Map<String, Object> extractCredentialSubjectProperties(VCCredentialResponse vcCredentialResponse);

    /**
     * Load display properties from well-known configuration
     */
    LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> loadDisplayPropertiesFromWellknown(
            Map<String, Object> credentialProperties,
            CredentialsSupportedResponse credentialsSupportedResponse,
            String userLocale);

    /**
     * Configure format-specific fields in the credential request builder
     */
    void configureCredentialRequest(VCCredentialRequest.VCCredentialRequestBuilder builder,
                                    CredentialsSupportedResponse credentialsSupportedResponse,
                                    String credentialType);

    /**
     * Get the supported format for this processor
     */
    List<String> getSupportedFormats();
}