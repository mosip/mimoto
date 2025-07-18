package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.service.CredentialFormatHandler;
import io.mosip.mimoto.util.LocaleUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.*;

@Slf4j
@Component
public class SdJwtCredentialFormatHandler implements CredentialFormatHandler {
    @Autowired
    private ObjectMapper objectMapper;

    @Override
    public Map<String, Object> extractCredentialSubjectProperties(VCCredentialResponse vcCredentialResponse) {
        return extractClaimsFromSdJwt((String) vcCredentialResponse.getCredential());
    }

    @Override
    public LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> loadDisplayPropertiesFromWellknown(
            Map<String, Object> credentialProperties,
            CredentialsSupportedResponse credentialsSupportedResponse,
            String userLocale) {

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProperties = new LinkedHashMap<>();

        // SD-JWT format — 'claims' is Map<String, Object> and needs conversion
        Map<String, Object> rawClaims = credentialsSupportedResponse.getClaims();

        Map<String, CredentialDisplayResponseDto> convertedClaimsMap = new HashMap<>();
        if (rawClaims != null) {
            rawClaims.forEach((key, value) -> {
                CredentialDisplayResponseDto dto = objectMapper.convertValue(value, CredentialDisplayResponseDto.class);
                convertedClaimsMap.put(key, dto);
            });
        }

        Map<String, CredentialDisplayResponseDto> displayConfigMap = convertedClaimsMap;
        List<String> orderedKeys = credentialsSupportedResponse.getOrder();

        if (displayConfigMap == null) {
            log.warn("No display configuration found for SD-JWT format");
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

    private Map<String, Object> extractClaimsFromSdJwt(String sdJwt) {
        try {
            String[] parts = sdJwt.split("\\.");
            if (parts.length < 2) {
                log.error("Invalid SD-JWT format");
                return Collections.emptyMap();
            }
            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            Map<String, Object> payload = objectMapper.readValue(payloadJson, Map.class);

            Object credentialSubject = payload.get("credentialSubject");
            if (credentialSubject instanceof Map) {
                return (Map<String, Object>) credentialSubject;
            } else {
                return payload; // fallback if claims are flattened
            }
        } catch (Exception e) {
            log.error("Error parsing SD-JWT", e);
            return Collections.emptyMap();
        }
    }

    @Override
    public void configureCredentialRequest(VCCredentialRequest.VCCredentialRequestBuilder builder,
                                           CredentialsSupportedResponse credentialsSupportedResponse,
                                           String credentialType) {
        // SD-JWT specific configuration
        builder.sdJwtVct(credentialType);
    }

    @Override
    public String getSupportedFormat() {
        return "vc+sd-jwt";
    }
}
