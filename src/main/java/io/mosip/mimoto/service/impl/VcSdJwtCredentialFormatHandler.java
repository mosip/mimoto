package io.mosip.mimoto.service.impl;


import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.CredentialFormat;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.service.CredentialFormatHandler;
import io.mosip.mimoto.util.LocaleUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.*;

@Slf4j
@Component("vc+sd-jwt")
public class VcSdJwtCredentialFormatHandler implements CredentialFormatHandler {

    @Autowired
    private ObjectMapper objectMapper;

    @Override
    public String getSupportedFormat() {
        return CredentialFormat.VC_SD_JWT.getFormat();
    }


    @Override
    public VCCredentialRequest buildCredentialRequest(VCCredentialRequestProof proof, CredentialsSupportedResponse credentialsSupportedResponse, String credentialType) {
        return VCCredentialRequest.builder().format(getSupportedFormat()).proof(proof).vct(credentialType).build();
    }

    @Override
    public Map<String, Object> extractCredentialClaims(VCCredentialResponse vcCredentialResponse) {
        Object credential = vcCredentialResponse.getCredential();
        if (credential instanceof String) {
            return extractClaimsFromSdJwt((String) credential);
        }
        log.warn("Unexpected credential format for SD-JWT VC: {}", credential);
        return Collections.emptyMap();
    }

    @Override
    public LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> loadDisplayPropertiesFromWellknown(
            Map<String, Object> credentialProperties,
            CredentialsSupportedResponse credentialsSupportedResponse,
            String userLocale) {

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProperties = new LinkedHashMap<>();

        // Remove "credentialSubject" and "disclosures" from credentialProperties
        Map<String, Object> filteredCredentialProperties = new HashMap<>();

        credentialProperties.forEach((outerKey, outerValue) -> {
            if (outerValue instanceof Map) {
                Map<?, ?> innerMap = (Map<?, ?>) outerValue;
                for (Map.Entry<?, ?> innerEntry : innerMap.entrySet()) {
                    if (innerEntry.getKey() instanceof String) {
                        filteredCredentialProperties.put((String) innerEntry.getKey(), innerEntry.getValue());
                    }
                }
            } else {
                filteredCredentialProperties.put(outerKey, outerValue);
            }
        });

        // Extract raw claims and convert to DTOs
        Map<String, Object> rawClaims = credentialsSupportedResponse.getClaims();
        if (rawClaims != null && rawClaims.size() == 1
                && rawClaims.values().iterator().next() instanceof Map) {
            rawClaims = (Map<String, Object>) rawClaims.values().iterator().next();
        }

        Map<String, CredentialDisplayResponseDto> convertedClaimsMap = new HashMap<>();
        if (rawClaims != null) {
            rawClaims.forEach((key, value) -> {
                CredentialDisplayResponseDto dto = objectMapper.convertValue(value, CredentialDisplayResponseDto.class);
                convertedClaimsMap.put(key, dto);
            });
        }

        if (convertedClaimsMap.isEmpty()) {
            log.warn("No display configuration found for SD-JWT format");
            return displayProperties;
        }

        String resolvedLocale = LocaleUtils.resolveLocaleWithFallback(convertedClaimsMap, userLocale);
        LinkedHashMap<String, CredentialIssuerDisplayResponse> localizedDisplayMap = new LinkedHashMap<>();

        if (resolvedLocale != null) {
            convertedClaimsMap.forEach((key, dto) -> {
                dto.getDisplay().stream()
                        .filter(display -> LocaleUtils.matchesLocale(display.getLocale(), resolvedLocale))
                        .findFirst()
                        .ifPresent(display -> localizedDisplayMap.put(key, display));
            });
        }

        List<String> orderedKeys = credentialsSupportedResponse.getOrder();
        List<String> fieldKeys = (orderedKeys != null && !orderedKeys.isEmpty())
                ? orderedKeys
                : new ArrayList<>(localizedDisplayMap.keySet());

        for (String key : fieldKeys) {
            CredentialIssuerDisplayResponse display = localizedDisplayMap.get(key);
            Object value = filteredCredentialProperties.get(key);
            if (display != null && value != null) {
                displayProperties.put(key, Map.of(display, value));
            }
        }

        return displayProperties;
    }

    public Map<String, Object> extractClaimsFromSdJwt(String sdJwtString) {
        try {
            SDJWT sdJwt = SDJWT.parse(sdJwtString);
            Map<String, Object> disclosedClaims = new HashMap<>();

            // Parse JWT payload
            String credentialJwt = sdJwt.getCredentialJwt();
            if (credentialJwt != null) {
                Map<String, Object> jwtPayload = parseJwtPayload(credentialJwt);
                if (jwtPayload != null) {
                    // Check if 'credentialSubject' is present
                    if (jwtPayload.containsKey("credentialSubject")) {
                        Object credentialSubject = jwtPayload.get("credentialSubject");
                        if (credentialSubject instanceof Map) {
                            disclosedClaims.putAll((Map<String, Object>) credentialSubject);
                        }
                    } else {
                        // No credentialSubject, put all claims at root level
                        disclosedClaims.putAll(jwtPayload);
                    }
                }
            }

            // Add disclosures
            List<Disclosure> disclosures = sdJwt.getDisclosures();
            Map<String, Object> disclosuresClaims = new HashMap<>();
            if (disclosures != null && !disclosures.isEmpty()) {
                for (Disclosure disclosure : disclosures) {
                    try {
                        String claimName = disclosure.getClaimName();
                        Object claimValue = disclosure.getClaimValue();

                        if (claimName != null && claimValue != null) {
                            disclosuresClaims.put(claimName, claimValue);
                        }
                    } catch (Exception e) {
                        log.warn("Failed to process disclosure: {}", e.getMessage());
                    }
                }
            }

            // Remove standard JWT claims and SD-JWT metadata
            List<String> metadataKeys = Arrays.asList("iss", "sub", "aud", "exp", "nbf", "iat", "jti", "_sd", "_sd_alg");
            metadataKeys.forEach(disclosedClaims::remove);

            // Separate credentialSubject if present
            Map<String, Object> result = new HashMap<>();
            result.put("credentialSubject", disclosedClaims);
            result.put("disclosures", disclosuresClaims);

            return result;

        } catch (IllegalArgumentException e) {
            log.error("Error parsing SD-JWT with Authlete library: {}", e.getMessage(), e);
            return Collections.emptyMap();
        } catch (Exception e) {
            log.error("Unexpected error processing SD-JWT", e);
            return Collections.emptyMap();
        }
    }

    private Map<String, Object> parseJwtPayload(String jwt) {
        try {
            String[] parts = jwt.split("\\.");
            if (parts.length < 2) {
                log.error("Invalid JWT format");
                return null;
            }

            String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            return objectMapper.readValue(payloadJson, Map.class);
        } catch (Exception e) {
            log.error("Error parsing JWT payload", e);
            return null;
        }
    }

}