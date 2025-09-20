package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.mimoto.UserMetadataDTO;
import io.mosip.mimoto.dto.openid.presentation.ConstraintsDTO;
import io.mosip.mimoto.dto.openid.presentation.FieldDTO;
import io.mosip.mimoto.dto.openid.presentation.FilterDTO;
import io.mosip.mimoto.dto.openid.presentation.InputDescriptorDTO;
import io.mosip.mimoto.dto.MatchingCredentialsResponseDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationDefinitionDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.VPNotCreatedException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
@Slf4j
public class SessionManager {

    @Autowired
    private ObjectMapper objectMapper;

    public void setupSession(HttpServletRequest request, String provider, UserMetadataDTO userMetadata, String userId) {
        HttpSession session = request.getSession(true);
        session.setAttribute("clientRegistrationId", provider);
        session.setAttribute(SessionKeys.USER_METADATA, userMetadata);
        session.setAttribute(SessionKeys.USER_ID, userId);
    }

    public void storePresentationSessionDataInSession(HttpSession httpSession, VerifiablePresentationSessionData sessionData, String presentationId, String walletId) {
        Map<String, String> presentations = (Map<String, String>) httpSession.getAttribute("presentations");

        if (presentations == null) {
            presentations = new HashMap<>();
        }

        // Adds the new presentation to the map if it is not already present
        presentations.computeIfAbsent(presentationId, id -> {
            try {
                Map<String, Object> vpSessionData = new HashMap<>();
                vpSessionData.put("createdAt", sessionData.getCreatedAt().toString());
                vpSessionData.put("openID4VPInstance", objectMapper.writeValueAsString(sessionData.getOpenID4VP()));
                vpSessionData.put("walletId", walletId);

                return objectMapper.writeValueAsString(vpSessionData);
            } catch (JsonProcessingException e) {
                log.error("Failed to store presentation details into session", e);
                throw new VPNotCreatedException("Failed to serialize presentation data - " + e.getMessage());
            }
        });

        // Store the updated presentations map in the session
        httpSession.setAttribute("presentations", presentations);
    }

    /**
     * Retrieves the presentation definition from session for a given presentation
     * ID.
     *
     * @param httpSession    The HTTP session.
     * @param presentationId The presentation ID.
     * @return The presentation definition if found, null otherwise.
     */
    public PresentationDefinitionDTO getPresentationDefinitionFromSession(HttpSession httpSession, String presentationId) {
        try {
            Map<String, String> presentations = (Map<String, String>) httpSession.getAttribute("presentations");
            if (presentations == null || !presentations.containsKey(presentationId)) {
                log.warn("No presentation found in session for presentationId: {}", presentationId);
                return null;
            }

            String presentationData = presentations.get(presentationId);
            Map<String, Object> vpSessionData = objectMapper.readValue(presentationData, Map.class);

            String openID4VPInstanceJson = (String) vpSessionData.get("openID4VPInstance");
            if (openID4VPInstanceJson == null) {
                log.warn("No openID4VPInstance found in session for presentationId: {}", presentationId);
                return null;
            }

            try {
                Map<String, Object> openID4VPInstance = objectMapper.readValue(openID4VPInstanceJson, Map.class);
                return extractPresentationDefinitionFromOpenID4VP(openID4VPInstance, presentationId);
            } catch (JsonProcessingException e) {
                log.warn("Failed to parse openID4VPInstance for presentationId: {}", presentationId, e);
                return null;
            }

        } catch (JsonProcessingException e) {
            log.error("Failed to retrieve presentation definition from session for presentationId: {}", presentationId, e);
            return null;
        }
    }

    private PresentationDefinitionDTO extractPresentationDefinitionFromOpenID4VP(Map<String, Object> openID4VPInstance, String presentationId) {
        Map<String, Object> authorizationRequest = (Map<String, Object>) openID4VPInstance.get("authorizationRequest");
        if (authorizationRequest == null) {
            log.warn("No authorizationRequest found in openID4VPInstance for presentationId: {}", presentationId);
            return null;
        }

        Map<String, Object> presentationDefinition = (Map<String, Object>) authorizationRequest.get("presentationDefinition");
        if (presentationDefinition == null) {
            log.warn("No presentationDefinition found in authorizationRequest for presentationId: {}", presentationId);
            return null;
        }

        PresentationDefinitionDTO dto = new PresentationDefinitionDTO();
        dto.setId((String) presentationDefinition.get("id"));
        
        List<Map<String, Object>> inputDescriptorsList = (List<Map<String, Object>>) presentationDefinition.get("inputDescriptors");
        if (inputDescriptorsList != null) {
            dto.setInputDescriptors(processInputDescriptors(inputDescriptorsList));
        }

        return dto;
    }

    private List<InputDescriptorDTO> processInputDescriptors(List<Map<String, Object>> inputDescriptorsList) {
        return inputDescriptorsList.stream()
                .map(this::buildInputDescriptorDTO)
                .collect(java.util.stream.Collectors.toList());
    }

    private InputDescriptorDTO buildInputDescriptorDTO(Map<String, Object> inputDescriptor) {
        InputDescriptorDTO dto = new InputDescriptorDTO();
        dto.setId((String) inputDescriptor.get("id"));
        dto.setFormat((Map<String, Map<String, List<String>>>) inputDescriptor.get("format"));
        
        Map<String, Object> constraints = (Map<String, Object>) inputDescriptor.get("constraints");
        if (constraints != null) {
            dto.setConstraints(buildConstraintsDTO(constraints));
        }
        
        return dto;
    }

    private ConstraintsDTO buildConstraintsDTO(Map<String, Object> constraints) {
        ConstraintsDTO dto = new ConstraintsDTO();
        dto.setLimitDisclosure((String) constraints.get("limitDisclosure"));
        
        List<Map<String, Object>> fieldsList = (List<Map<String, Object>>) constraints.get("fields");
        if (fieldsList != null) {
            FieldDTO[] fields = fieldsList.stream()
                    .map(this::buildFieldDTO)
                    .toArray(FieldDTO[]::new);
            dto.setFields(fields);
        }
        
        return dto;
    }

    private FieldDTO buildFieldDTO(Map<String, Object> field) {
        FieldDTO dto = new FieldDTO();
        
        List<String> path = (List<String>) field.get("path");
        dto.setPath(path != null ? path.toArray(new String[0]) : new String[0]);
        
        Map<String, Object> filter = (Map<String, Object>) field.get("filter");
        if (filter != null) {
            FilterDTO filterDTO = new FilterDTO();
            filterDTO.setType((String) filter.get("type"));
            filterDTO.setPattern((String) filter.get("pattern"));
            dto.setFilter(filterDTO);
        }
        
        return dto;
    }

    /**
     * Stores the matching credentials response in the session cache.
     *
     * @param httpSession The HTTP session.
     * @param presentationId The presentation ID.
     * @param matchingCredentialsResponse The matching credentials response to cache.
     */
    public void storeMatchingCredentialsInSession(HttpSession httpSession, String presentationId, MatchingCredentialsResponseDTO matchingCredentialsResponse) {
        try {
            Map<String, String> matchingCredentialsCache = (Map<String, String>) httpSession.getAttribute("matchingCredentials");
            
            if (matchingCredentialsCache == null) {
                matchingCredentialsCache = new HashMap<>();
            }
            
            String matchingCredentialsJson = objectMapper.writeValueAsString(matchingCredentialsResponse);
            matchingCredentialsCache.put(presentationId, matchingCredentialsJson);
            
            httpSession.setAttribute("matchingCredentials", matchingCredentialsCache);
            
        } catch (JsonProcessingException e) {
            log.error("Failed to store matching credentials in session cache for presentationId: {}", presentationId, e);
            throw new VPNotCreatedException("Failed to cache matching credentials - " + e.getMessage());
        }
    }

    /**
     * Retrieves the matching credentials response from the session cache.
     *
     * @param httpSession The HTTP session.
     * @param presentationId The presentation ID.
     * @return The matching credentials response if found in cache, null otherwise.
     */
    public MatchingCredentialsResponseDTO getMatchingCredentialsFromSession(HttpSession httpSession, String presentationId) {
        try {
            Map<String, String> matchingCredentialsCache = (Map<String, String>) httpSession.getAttribute("matchingCredentials");
            
            if (matchingCredentialsCache == null || !matchingCredentialsCache.containsKey(presentationId)) {
                log.info("No matching credentials found in session cache for presentationId: {}", presentationId);
                return null;
            }
            
            String matchingCredentialsJson = matchingCredentialsCache.get(presentationId);
            MatchingCredentialsResponseDTO matchingCredentialsResponse = objectMapper.readValue(matchingCredentialsJson, MatchingCredentialsResponseDTO.class);
            
            return matchingCredentialsResponse;
            
        } catch (JsonProcessingException e) {
            log.error("Failed to retrieve matching credentials from session cache for presentationId: {}", presentationId, e);
            return null;
        }
    }
}
