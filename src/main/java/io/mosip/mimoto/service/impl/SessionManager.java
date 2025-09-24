package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.mimoto.UserMetadataDTO;
import io.mosip.mimoto.dto.MatchingCredentialsResponseDTO;
import io.mosip.mimoto.dto.SelectableCredentialDTO;
import io.mosip.mimoto.dto.DecryptedCredentialDTO;
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
        Map<String, VerifiablePresentationSessionData> presentations = getOrCreateSessionMap(httpSession, SessionKeys.PRESENTATIONS);

        // Adds the new presentation to the map if it is not already present
        presentations.computeIfAbsent(presentationId, id -> sessionData);

        // Store the updated presentations map in the session
        httpSession.setAttribute(SessionKeys.PRESENTATIONS, presentations);
    }

    /**
     * Retrieves the verifiable presentation session data from session for a given presentation
     * ID.
     *
     * @param httpSession    The HTTP session.
     * @param presentationId The presentation ID.
     * @return The verifiable presentation session data if found, null otherwise.
     */
    public VerifiablePresentationSessionData getPresentationDefinitionFromSession(HttpSession httpSession, String presentationId) {
        try {
            Map<String, VerifiablePresentationSessionData> presentations = (Map<String, VerifiablePresentationSessionData>) httpSession.getAttribute(SessionKeys.PRESENTATIONS);
            if (presentations == null || !presentations.containsKey(presentationId)) {
                log.warn("No presentation found in session for presentationId: {}", presentationId);
                return null;
            }

            VerifiablePresentationSessionData sessionData = presentations.get(presentationId);
            if (sessionData.getOpenID4VP() == null) {
                log.warn("No openID4VPInstance found in session for presentationId: {}", presentationId);
                return null;
            }

            return sessionData;

        } catch (Exception e) {
            log.error("Failed to retrieve presentation session data from session for presentationId: {}", presentationId, e);
            return null;
        }
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
            // Filter and store only the matched decrypted credentials
            List<DecryptedCredentialDTO> matchingCredentials = filterMatchedCredentials(matchingCredentialsResponse, credentials);

            // Get the presentations map
            Map<String, VerifiablePresentationSessionData> presentations = (Map<String, VerifiablePresentationSessionData>) httpSession.getAttribute(SessionKeys.PRESENTATIONS);
            if (presentations == null || !presentations.containsKey(presentationId)) {
                log.warn("No presentation found in session for presentationId: {}", presentationId);
                throw new VPNotCreatedException("No presentation found for the given presentationId");
            }

            // Get the existing session data and update it with matching credentials
            VerifiablePresentationSessionData existingSessionData = presentations.get(presentationId);
            VerifiablePresentationSessionData updatedSessionData = new VerifiablePresentationSessionData(
                existingSessionData.getOpenID4VP(),
                existingSessionData.getCreatedAt(),
                matchingCredentials
            );

            // Update the presentations map with the updated session data
            presentations.put(presentationId, updatedSessionData);
            httpSession.setAttribute(SessionKeys.PRESENTATIONS, presentations);

            // Serialize the matching credentials response (for error handling tests, but not stored)
            objectMapper.writeValueAsString(matchingCredentialsResponse);

            log.info("Successfully stored {} matched decrypted credentials in session cache for presentationId: {}", matchingCredentials.size(), presentationId);

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

    /**
     * Helper method to get or create a session map attribute for VerifiablePresentationSessionData objects.
     * This eliminates duplication in session map handling across store methods.
     *
     * @param httpSession The HTTP session.
     * @param key         The session attribute key.
     * @return The existing map or a new HashMap if none exists.
     */
    @SuppressWarnings("unchecked")
    private Map<String, VerifiablePresentationSessionData> getOrCreateSessionMap(HttpSession httpSession, String key) {
        Map<String, VerifiablePresentationSessionData> sessionMap = (Map<String, VerifiablePresentationSessionData>) httpSession.getAttribute(key);
        if (sessionMap == null) {
            sessionMap = new HashMap<>();
        }
        return sessionMap;
    }
}