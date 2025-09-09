package io.mosip.mimoto.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.mimoto.UserMetadataDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.VPNotCreatedException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.HashMap;
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

    public void storePresentationSessionDataInSession(HttpSession httpSession, VerifiablePresentationSessionData sessionData, String presentationId, String walletId) throws JsonProcessingException{
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
}
