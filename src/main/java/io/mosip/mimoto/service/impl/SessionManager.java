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
import io.mosip.mimoto.dto.SelectableCredentialDTO;
import io.mosip.mimoto.dto.DecryptedCredentialDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationDefinitionDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.VPNotCreatedException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Component
@Slf4j
public class SessionManager {

    @Autowired
    private ObjectMapper objectMapper;

    public void setupSession(HttpServletRequest request, String provider, UserMetadataDTO userMetadata, String userId) {
        HttpSession session = request.getSession(true);
        session.setAttribute(SessionKeys.CLIENT_REGISTRATION_ID, provider);
        session.setAttribute(SessionKeys.USER_METADATA, userMetadata);
        session.setAttribute(SessionKeys.USER_ID, userId);
    }

    public void storePresentationSessionDataInSession(HttpSession httpSession, VerifiablePresentationSessionData sessionData, String presentationId, String walletId) {
        Map<String, String> presentations = (Map<String, String>) httpSession.getAttribute(SessionKeys.PRESENTATIONS);

        if (presentations == null) {
            presentations = new HashMap<>();
        }

        // Adds the new presentation to the map if it is not already present
        presentations.computeIfAbsent(presentationId, id -> {
            try {
                Map<String, Object> vpSessionData = new HashMap<>();
                vpSessionData.put(SessionKeys.CREATED_AT, sessionData.getCreatedAt().toString());
                vpSessionData.put(SessionKeys.OPENID4VP_INSTANCE, objectMapper.writeValueAsString(sessionData.getOpenID4VP()));
                vpSessionData.put(SessionKeys.WALLET_ID, walletId);

                return objectMapper.writeValueAsString(vpSessionData);
            } catch (JsonProcessingException e) {
                log.error("Failed to store presentation details into session", e);
                throw new VPNotCreatedException("Failed to serialize presentation data - " + e.getMessage());
            }
        });

        // Store the updated presentations map in the session
        httpSession.setAttribute(SessionKeys.PRESENTATIONS, presentations);
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
            Map<String, String> presentations = (Map<String, String>) httpSession.getAttribute(SessionKeys.PRESENTATIONS);
            if (presentations == null || !presentations.containsKey(presentationId)) {
                log.warn("No presentation found in session for presentationId: {}", presentationId);
                return null;
            }

            String presentationData = presentations.get(presentationId);
            Map<String, Object> vpSessionData = objectMapper.readValue(presentationData, Map.class);

            String openID4VPInstanceJson = (String) vpSessionData.get(SessionKeys.OPENID4VP_INSTANCE);
            if (openID4VPInstanceJson == null) {
                log.warn("No openID4VPInstance found in session for presentationId: {}", presentationId);
                return null;
            }

            Map<String, Object> openID4VPInstance = objectMapper.readValue(openID4VPInstanceJson, Map.class);
            return extractPresentationDefinitionFromOpenID4VP(openID4VPInstance, presentationId);

        } catch (JsonProcessingException e) {
            log.error("Failed to retrieve presentation definition from session for presentationId: {}", presentationId, e);
            return null;
        }
    }

    private PresentationDefinitionDTO extractPresentationDefinitionFromOpenID4VP(Map<String, Object> openID4VPInstance, String presentationId) {
        Map<String, Object> authorizationRequest = (Map<String, Object>) openID4VPInstance.get(SessionKeys.AUTHORIZATION_REQUEST);
        if (authorizationRequest == null) {
            log.warn("No authorizationRequest found in openID4VPInstance for presentationId: {}", presentationId);
            return null;
        }

        Map<String, Object> presentationDefinition = (Map<String, Object>) authorizationRequest.get(SessionKeys.PRESENTATION_DEFINITION);
        if (presentationDefinition == null) {
            log.warn("No presentationDefinition found in authorizationRequest for presentationId: {}", presentationId);
            return null;
        }

        PresentationDefinitionDTO dto = new PresentationDefinitionDTO();
        dto.setId((String) presentationDefinition.get(SessionKeys.ID));

        List<Map<String, Object>> inputDescriptorsList = (List<Map<String, Object>>) presentationDefinition.get(SessionKeys.INPUT_DESCRIPTORS);
        if (inputDescriptorsList != null) {
            dto.setInputDescriptors(processInputDescriptors(inputDescriptorsList));
        }

        return dto;
    }

    private List<InputDescriptorDTO> processInputDescriptors(List<Map<String, Object>> inputDescriptorsList) {
        return inputDescriptorsList.stream().map(this::buildInputDescriptorDTO).collect(java.util.stream.Collectors.toList());
    }

    private InputDescriptorDTO buildInputDescriptorDTO(Map<String, Object> inputDescriptor) {
        InputDescriptorDTO dto = new InputDescriptorDTO();
        dto.setId((String) inputDescriptor.get(SessionKeys.ID));
        dto.setFormat((Map<String, Map<String, List<String>>>) inputDescriptor.get(SessionKeys.FORMAT));

        Map<String, Object> constraints = (Map<String, Object>) inputDescriptor.get(SessionKeys.CONSTRAINTS);
        if (constraints != null) {
            dto.setConstraints(buildConstraintsDTO(constraints));
        }

        return dto;
    }

    private ConstraintsDTO buildConstraintsDTO(Map<String, Object> constraints) {
        ConstraintsDTO dto = new ConstraintsDTO();
        dto.setLimitDisclosure((String) constraints.get(SessionKeys.LIMIT_DISCLOSURE));

        List<Map<String, Object>> fieldsList = (List<Map<String, Object>>) constraints.get(SessionKeys.FIELDS);
        if (fieldsList != null) {
            FieldDTO[] fields = fieldsList.stream().map(this::buildFieldDTO).toArray(FieldDTO[]::new);
            dto.setFields(fields);
        }

        return dto;
    }

    private FieldDTO buildFieldDTO(Map<String, Object> field) {
        FieldDTO dto = new FieldDTO();

        List<String> path = (List<String>) field.get(SessionKeys.PATH);
        dto.setPath(path != null ? path.toArray(new String[0]) : new String[0]);

        Map<String, Object> filter = (Map<String, Object>) field.get(SessionKeys.FILTER);
        if (filter != null) {
            FilterDTO filterDTO = new FilterDTO();
            filterDTO.setType((String) filter.get(SessionKeys.TYPE));
            filterDTO.setPattern((String) filter.get(SessionKeys.PATTERN));
            dto.setFilter(filterDTO);
        }

        return dto;
    }

    /**
     * Stores the matching credentials response and filtered decrypted credentials in the session cache.
     *
     * @param httpSession                 The HTTP session.
     * @param presentationId              The presentation ID.
     * @param matchingCredentialsResponse The matching credentials response to cache.
     * @param credentials                 The decrypted credentials to cache.
     */
    public void storeMatchingWalletCredentialsInSession(HttpSession httpSession, String presentationId, MatchingCredentialsResponseDTO matchingCredentialsResponse, List<DecryptedCredentialDTO> credentials) {
        try {
            // Store the matching credentials response
            Map<String, String> matchingCredentialsCache = (Map<String, String>) httpSession.getAttribute(SessionKeys.MATCHING_CREDENTIALS);

            if (matchingCredentialsCache == null) {
                matchingCredentialsCache = new HashMap<>();
            }

            String matchingCredentialsJson = objectMapper.writeValueAsString(matchingCredentialsResponse);
            matchingCredentialsCache.put(presentationId, matchingCredentialsJson);

            httpSession.setAttribute(SessionKeys.MATCHING_CREDENTIALS, matchingCredentialsCache);

            // Filter and store only the matched decrypted credentials
            List<DecryptedCredentialDTO> matchedCredentials = filterMatchedCredentials(matchingCredentialsResponse, credentials);

            Map<String, String> matchedCredentialsCache = (Map<String, String>) httpSession.getAttribute(SessionKeys.MATCHED_CREDENTIALS);

            if (matchedCredentialsCache == null) {
                matchedCredentialsCache = new HashMap<>();
            }

            String matchedCredentialsJson = objectMapper.writeValueAsString(matchedCredentials);
            matchedCredentialsCache.put(presentationId, matchedCredentialsJson);

            httpSession.setAttribute(SessionKeys.MATCHED_CREDENTIALS, matchedCredentialsCache);

            log.info("Successfully stored matching credentials and {} matched decrypted credentials in session cache for presentationId: {}", matchedCredentials.size(), presentationId);

        } catch (JsonProcessingException e) {
            log.error("Failed to store matching credentials in session cache for presentationId: {}", presentationId, e);
            throw new VPNotCreatedException("Failed to cache matching credentials - " + e.getMessage());
        }
    }

    /**
     * Filters decrypted credentials to only include those that match the credential IDs from the matching response.
     *
     * @param matchingCredentialsResponse The matching credentials response containing credential IDs.
     * @param decryptedCredentials        The complete decrypted credentials.
     * @return Filtered list of decrypted credentials that match the credential IDs.
     */
    private List<DecryptedCredentialDTO> filterMatchedCredentials(MatchingCredentialsResponseDTO matchingCredentialsResponse, List<DecryptedCredentialDTO> decryptedCredentials) {

        if (matchingCredentialsResponse == null || matchingCredentialsResponse.getAvailableCredentials() == null || matchingCredentialsResponse.getAvailableCredentials().isEmpty()) {
            return new ArrayList<>();
        }

        // Extract credential IDs from the matching response
        Set<String> matchedCredentialIds = matchingCredentialsResponse.getAvailableCredentials().stream().map(SelectableCredentialDTO::getCredentialId).collect(Collectors.toSet());

        // Filter decrypted credentials to only include matched ones
        List<DecryptedCredentialDTO> filteredCredentials = decryptedCredentials.stream().filter(credential -> matchedCredentialIds.contains(credential.getId())).collect(Collectors.toList());

        log.info("Filtered {} matched decrypted credentials from {} total decrypted credentials", filteredCredentials.size(), decryptedCredentials.size());

        return filteredCredentials;
    }
}
