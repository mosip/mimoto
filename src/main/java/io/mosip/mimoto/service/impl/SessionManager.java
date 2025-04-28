package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.mimoto.UserMetadataDTO;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Component;

@Component
public class SessionManager {
    public void setupSession(HttpServletRequest request, String provider, UserMetadataDTO userMetadata, String userId) {
        HttpSession session = request.getSession(true);
        session.setAttribute("clientRegistrationId", provider);
        session.setAttribute(SessionKeys.USER_METADATA, userMetadata);
        session.setAttribute(SessionKeys.USER_ID, userId);
    }
}
