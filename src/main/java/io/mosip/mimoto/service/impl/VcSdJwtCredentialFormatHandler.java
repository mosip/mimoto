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
import java.util.stream.Collectors;

import static io.mosip.mimoto.util.IssuerConfigUtil.camelToTitleCase;
import static io.mosip.mimoto.util.JwtUtils.parseJwtPayload;

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
    public VCCredentialRequest buildCredentialRequest(VCCredentialRequestProof proof, CredentialsSupportedResponse credentialsSupportedResponse) {
        return VCCredentialRequest.builder().format(getSupportedFormat()).proof(proof).vct(credentialsSupportedResponse.getVct()).build();
    }

    @Override
    public Map<String, Object> extractCredentialClaims(VCCredentialResponse vcCredentialResponse) {
        Object credential = vcCredentialResponse.getCredential();
        if (credential instanceof String) {
            return extractClaimsFromSdJwt((String) credential);
        }
        log.warn("Unexpected credential format in response for SD-JWT VC:");
        return Collections.emptyMap();
    }

    @Override
    public LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> loadDisplayPropertiesFromWellknown(
            Map<String, Object> credentialProperties,
            CredentialsSupportedResponse credentialsSupportedResponse,
            String userLocale) {

        LinkedHashMap<String, Map<CredentialIssuerDisplayResponse, Object>> displayProperties = new LinkedHashMap<>();

        // Extract raw claims and convert to DTOs
        Map<String, Object> rawClaims = Optional.ofNullable(credentialsSupportedResponse.getClaims())
                .map(map -> (map.size() == 1 && map.values().iterator().next() instanceof Map)
                        ? (Map<String, Object>) map.values().iterator().next()
                        : map)
                .orElse(Collections.emptyMap());

        Map<String, CredentialDisplayResponseDto> convertedClaimsMap = rawClaims.entrySet().stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        entry -> objectMapper.convertValue(entry.getValue(), CredentialDisplayResponseDto.class)
                ));

        if (convertedClaimsMap.isEmpty()) {
            log.warn("No display configuration found for SD-JWT format");
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

        // Start with ordered fields
        Set<String> orderedKeys = Optional.ofNullable(credentialsSupportedResponse.getOrder())
                .map(LinkedHashSet::new) // preserve order
                .orElse(new LinkedHashSet<>());

        // Add remaining keys from credentialProperties that are not already in orderedKeys
        for (String key : credentialProperties.keySet()) {
            orderedKeys.add(key); // Set ensures no duplicates
        }

        for (String key : orderedKeys) {
            Object value = credentialProperties.get(key);
            if (value == null) {
                continue; // Skip fields without a value
            }

            CredentialIssuerDisplayResponse display = localizedDisplayMap.get(key);

            // Fallback if not found in metadata
            if (display == null) {
                display = new CredentialIssuerDisplayResponse();
                display.setName(camelToTitleCase(key));
                display.setLocale("en");
            }

            displayProperties.put(key, Map.of(display, value));
        }

        return displayProperties;
    }



    public Map<String, Object> extractClaimsFromSdJwt(String sdJwtString) {
        try {
            SDJWT sdJwt = SDJWT.parse(sdJwtString);
            Map<String, Object> claims = new HashMap<>();

            // Parse JWT payload
            String credentialJwt = sdJwt.getCredentialJwt();
            if (credentialJwt != null) {
                Map<String, Object> jwtPayload = parseJwtPayload(credentialJwt);
                if (jwtPayload != null) {
                    claims.putAll(jwtPayload);
                }
            }

            // Add disclosures
            List<Disclosure> disclosures = sdJwt.getDisclosures();
            if (disclosures != null && !disclosures.isEmpty()) {
                for (Disclosure disclosure : disclosures) {
                    try {
                        String claimName = disclosure.getClaimName();
                        Object claimValue = disclosure.getClaimValue();

                        if (claimName != null && claimValue != null) {
                            claims.put(claimName, claimValue); // Add directly to claims
                        }
                    } catch (Exception e) {
                        log.warn("Failed to process disclosure: {}", e.getMessage());
                    }
                }
            }

            // Remove standard JWT claims and SD-JWT metadata
            List<String> metadataKeys = Arrays.asList("vct", "cnf", "iss", "sub", "aud", "exp", "nbf", "iat", "jti", "_sd", "_sd_alg");
            metadataKeys.forEach(claims::remove);

            // Return claims directly as result
            return claims;

        } catch (IllegalArgumentException e) {
            log.error("Error parsing SD-JWT with Authlete library: {}", e.getMessage(), e);
            return Collections.emptyMap();
        } catch (Exception e) {
            log.error("Unexpected error processing SD-JWT", e);
            return Collections.emptyMap();
        }
    }
}