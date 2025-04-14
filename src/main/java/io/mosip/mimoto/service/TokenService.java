package io.mosip.mimoto.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public interface TokenService {
    void processToken(String idToken, String provider, HttpServletRequest request, HttpServletResponse response) throws Exception;
}
