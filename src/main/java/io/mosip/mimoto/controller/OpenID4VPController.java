package io.mosip.mimoto.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.VerifiablePresentationResponseDTO;
import io.mosip.mimoto.dto.resident.VerifiablePresentationSessionData;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.service.OpenID4VPService;
import io.mosip.mimoto.util.WalletUtil;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/wallets/{walletId}/presentations")
public class OpenID4VPController {

    @Autowired
    private OpenID4VPService openID4VPService;

    @Autowired
    private ObjectMapper objectMapper;

    @PostMapping(consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<VerifiablePresentationResponseDTO> handleVPAuthorizationRequest(@PathVariable("walletId") String walletId, HttpSession httpSession, @RequestBody String urlEncodedVPAuthorizationRequest) throws ApiNotAccessibleException, IOException {
        String sessionWalletId = (String) httpSession.getAttribute(SessionKeys.WALLET_ID);
        if (sessionWalletId != null) {
            WalletUtil.validateWalletId(httpSession, walletId);
        }
        VerifiablePresentationResponseDTO verifiablePresentationResponseDTO = openID4VPService.handleVPAuthorizationRequest(urlEncodedVPAuthorizationRequest, walletId);
        storePresentationSessionDataInHttpSession(httpSession, verifiablePresentationResponseDTO.getVerifiablePresentationSessionData(), verifiablePresentationResponseDTO.getPresentationId());
        
        return ResponseEntity.status(HttpStatus.OK).body(verifiablePresentationResponseDTO);
    }

    public void storePresentationSessionDataInHttpSession(HttpSession httpSession, VerifiablePresentationSessionData sessionData, String presentationId) throws JsonProcessingException {
        Map<String, String> presentations = (Map<String, String>) httpSession.getAttribute("presentations");

        if (presentations == null) {
            presentations = new HashMap<>();
        }

        // Create a new presentation entry
        Map<String, Object> vpSessionData = new HashMap<>();
        vpSessionData.put("authorizationRequest", sessionData.getAuthorizationRequest());
        vpSessionData.put("createdAt", sessionData.getCreatedAt().toString());

        // Serialize the presentationData map to a JSON string
        String presentationDataJson = objectMapper.writeValueAsString(vpSessionData);

        // Add the new presentation to the map
        presentations.put(presentationId, presentationDataJson);

        // Store the updated map in the session
        httpSession.setAttribute("presentations", presentations);
    }
}
