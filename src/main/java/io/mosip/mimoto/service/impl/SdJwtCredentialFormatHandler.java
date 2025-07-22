package io.mosip.mimoto.service.impl;


import java.nio.charset.StandardCharsets;
import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.service.CredentialFormatHandler;
import io.mosip.mimoto.util.LocaleUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;

@Slf4j
@Component
public class SdJwtCredentialFormatHandler implements CredentialFormatHandler {

    @Autowired
    private ObjectMapper objectMapper;

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

    private Map<String, Object> extractClaimsFromSdJwt(String sdJwtString) {
        try {
            // Parse the SD-JWT using Authlete library
            SDJWT sdJwt = SDJWT.parse(sdJwtString);

            // Get all disclosed claims by processing disclosures
            Map<String, Object> disclosedClaims = new HashMap<>();

            // Manually parse the JWT payload from the credential JWT
            String credentialJwt = sdJwt.getCredentialJwt();
            if (credentialJwt != null) {
                Map<String, Object> jwtPayload = parseJwtPayload(credentialJwt);
                if (jwtPayload != null) {
                    disclosedClaims.putAll(jwtPayload);
                }
            }

            // Process disclosures to get selectively disclosed claims
            List<Disclosure> disclosures = sdJwt.getDisclosures();
            if (disclosures != null && !disclosures.isEmpty()) {
                for (Disclosure disclosure : disclosures) {
                    try {
                        // Get the claim name and value from disclosure
                        String claimName = disclosure.getClaimName();
                        Object claimValue = disclosure.getClaimValue();

                        if (claimName != null && claimValue != null) {
                            disclosedClaims.put(claimName, claimValue);
                        }
                    } catch (Exception e) {
                        log.warn("Failed to process disclosure: {}", e.getMessage());
                    }
                }
            }

            // Extract credentialSubject if present, otherwise return all claims
            Object credentialSubject = disclosedClaims.get("credentialSubject");
            if (credentialSubject instanceof Map) {
                return (Map<String, Object>) credentialSubject;
            } else {
                // Remove JWT standard claims that are not part of credential data
                Map<String, Object> credentialClaims = new HashMap<>(disclosedClaims);
                credentialClaims.remove("iss");
                credentialClaims.remove("sub");
                credentialClaims.remove("aud");
                credentialClaims.remove("exp");
                credentialClaims.remove("nbf");
                credentialClaims.remove("iat");
                credentialClaims.remove("jti");
                credentialClaims.remove("_sd");
                credentialClaims.remove("_sd_alg");

                return credentialClaims;
            }

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

    @Override
    public VCCredentialRequest configureCredentialRequest(VCCredentialRequest.VCCredentialRequestBuilder builder,
                                                          CredentialsSupportedResponse credentialsSupportedResponse,
                                                          String credentialType) {
        builder.vct(credentialType);
        return builder.build();
    }

    @Override
    public String getSupportedFormat() {
        return "dc+sd-jwt";
    }
}