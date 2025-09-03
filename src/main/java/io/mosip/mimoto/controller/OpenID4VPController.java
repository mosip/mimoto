package io.mosip.mimoto.controller;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.VerifiablePresentationResponseDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.service.OpenID4VPService;
import io.mosip.mimoto.util.WalletUtil;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@Slf4j
@RestController
@RequestMapping("/wallets/{walletId}/presentations")
public class OpenID4VPController {

    @Autowired
    OpenID4VPService openID4VPService;

    @PostMapping
    public ResponseEntity<VerifiablePresentationResponseDTO> handleVPAuthorizationRequest(@PathVariable("walletId") String walletId, HttpSession httpSession, @RequestBody String urlEncodedVPAuthorizationRequest) throws ApiNotAccessibleException, IOException {
        String sessionWalletId = (String) httpSession.getAttribute(SessionKeys.WALLET_ID);
        if (sessionWalletId != null) {
            WalletUtil.validateWalletId(httpSession, walletId);
        }
        VerifiablePresentationResponseDTO verifiablePresentationResponseDTO = openID4VPService.handleVPAuthorizationRequest(urlEncodedVPAuthorizationRequest, walletId);
        
        return ResponseEntity.status(HttpStatus.OK).body(verifiablePresentationResponseDTO);
    }
}
