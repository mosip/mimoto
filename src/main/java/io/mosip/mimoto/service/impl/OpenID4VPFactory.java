package io.mosip.mimoto.service.impl;

import io.mosip.openID4VP.OpenID4VP;
import org.springframework.stereotype.Component;

@Component
public class OpenID4VPFactory {
    public OpenID4VP create(String presentationId) {
        return new OpenID4VP(presentationId);
    }
}