package io.mosip.mimoto.service.impl;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Service;

@Service
public class SecurityContextManager {
    private final SecurityContextRepository securityContextRepository;

    public SecurityContextManager() {
        this.securityContextRepository = new HttpSessionSecurityContextRepository();
    }

    public void setupSecurityContext(OAuth2AuthenticationToken oauth2AuthenticationToken, HttpServletRequest request, HttpServletResponse response) {
        SecurityContext context = SecurityContextHolder.getContext();
        context.setAuthentication(oauth2AuthenticationToken);
        securityContextRepository.saveContext(context, request, response);
    }
}
