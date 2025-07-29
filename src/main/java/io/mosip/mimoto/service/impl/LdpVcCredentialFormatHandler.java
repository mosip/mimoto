package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.service.CredentialFormatHandler;
import io.mosip.mimoto.util.LocaleUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Component
public class LdpVcCredentialFormatHandler implements CredentialFormatHandler {

    @Autowired
    private ObjectMapper objectMapper;

    @Override
    public Map<String, Object> extractCredentialClaims(VCCredentialResponse vcCredentialResponse) {
        VCCredentialProperties credential = objectMapper.convertValue(vcCredentialResponse.getCredential(), VCCredentialProperties.class);
        return (Map<String, Object>) credential.getCredentialSubject();
    }

    @Override
    public LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> loadDisplayPropertiesFromWellknown(
            Map<String, Object> credentialProperties,
            CredentialsSupportedResponse credentialsSupportedResponse,
            String userLocale) {

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProperties = new LinkedHashMap<>();

        // LDP VC format — display config is in "credential_definition.credential_subject"
        if (credentialsSupportedResponse.getCredentialDefinition() == null ||
                credentialsSupportedResponse.getCredentialDefinition().getCredentialSubject() == null) {
            log.warn("Missing credential definition or credential subject for LDP VC format");
            return displayProperties;
        }

        Map<String, CredentialDisplayResponseDto> displayConfigMap =
                credentialsSupportedResponse.getCredentialDefinition().getCredentialSubject();
        List<String> orderedKeys = credentialsSupportedResponse.getOrder();

        if (displayConfigMap == null) {
            log.warn("No display configuration found for LDP VC format");
            return displayProperties;
        }

        String resolvedLocale = LocaleUtils.resolveLocaleWithFallback(displayConfigMap, userLocale);

        LinkedHashMap<String, CredentialIssuerDisplayResponse> localizedDisplayMap = new LinkedHashMap<>();

        if (resolvedLocale != null) {
            displayConfigMap.forEach((key, dto) -> {
                dto.getDisplay().stream()
                        .filter(display -> LocaleUtils.matchesLocale(display.getLocale(), resolvedLocale))
                        .findFirst()
                        .ifPresent(display -> localizedDisplayMap.put(key, display));
            });
        }

        List<String> fieldKeys = (orderedKeys != null && !orderedKeys.isEmpty())
                ? orderedKeys
                : new ArrayList<>(localizedDisplayMap.keySet());

        for (String key : fieldKeys) {
            CredentialIssuerDisplayResponse display = localizedDisplayMap.get(key);
            Object value = credentialProperties.get(key);
            if (display != null && value != null) {
                displayProperties.put(key, Map.of(display, value));
            }
        }

        return displayProperties;
    }

    @Override
    public VCCredentialRequest buildCredentialRequest(
            VCCredentialRequestProof proof,
            CredentialsSupportedResponse credentialsSupportedResponse,
            String credentialType) {

        List<String> credentialContext = credentialsSupportedResponse.getCredentialDefinition().getContext();
        if (credentialContext == null || credentialContext.isEmpty()) {
            credentialContext = List.of("https://www.w3.org/2018/credentials/v1");
        }

        return VCCredentialRequest.builder()
                .format(getSupportedFormat())  // Using internal format
                .proof(proof)
                .credentialDefinition(VCCredentialDefinition.builder()
                        .type(credentialsSupportedResponse.getCredentialDefinition().getType())
                        .context(credentialContext)
                        .build())
                .build();
    }

    @Override
    public String getSupportedFormat() {
        return CredentialFormat.LDP_VC.getFormat();
    }
}
