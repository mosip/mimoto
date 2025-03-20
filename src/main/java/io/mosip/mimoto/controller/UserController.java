package io.mosip.mimoto.controller;

import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.dbentity.UserMetadata;
import io.mosip.mimoto.dto.mimoto.UserMetadataDTO;
import io.mosip.mimoto.dto.WalletRequestDto;
import io.mosip.mimoto.exception.OAuth2AuthenticationException;
import io.mosip.mimoto.repository.UserMetadataRepository;
import io.mosip.mimoto.service.WalletService;
import io.mosip.mimoto.util.EncryptionDecryptionUtil;
import io.mosip.mimoto.util.Utilities;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static io.mosip.mimoto.exception.PlatformErrorMessages.*;

@Slf4j
@RestController
@RequestMapping(value = "/secure/user")
public class UserController {

    @Autowired
    private UserMetadataRepository userMetadataRepository;

    @Autowired
    private EncryptionDecryptionUtil encryptionDecryptionUtill;

    @Autowired
    private WalletService walletService;

    @GetMapping("/profile")
    public ResponseEntity<ResponseWrapper<UserMetadataDTO>> getUserProfile(Authentication authentication, HttpSession session) {
        try {
            ResponseWrapper<UserMetadataDTO> responseWrapper = new ResponseWrapper<>();
            String identityProvider = (String) session.getAttribute("clientRegistrationId");

            UserMetadata userMetadata = fetchUserMetadata(authentication.getName(), identityProvider);

            UserMetadataDTO userMetadataDTO = new UserMetadataDTO(encryptionDecryptionUtill.decrypt(userMetadata.getDisplayName(), "user_pii", "", ""),
                    encryptionDecryptionUtill.decrypt(userMetadata.getProfilePictureUrl(), "user_pii", "", ""),
                    encryptionDecryptionUtill.decrypt(userMetadata.getEmail(), "user_pii", "", ""));
            responseWrapper.setResponse(userMetadataDTO);

            return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
        } catch (OAuth2AuthenticationException exception) {
            log.error("Error occurred while retrieving user profile : ", exception);
            return Utilities.handleErrorResponse(exception, USER_METADATA_FETCH_EXCEPTION.getCode(), exception.getStatus(), null);
        } catch (DataAccessResourceFailureException exception) {
            log.error("Error occurred while connecting to the database : ", exception);
            OAuth2AuthenticationException authenticationException = new OAuth2AuthenticationException(DATABASE_CONNECTION_EXCEPTION.getCode(), DATABASE_CONNECTION_EXCEPTION.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
            return Utilities.handleErrorResponse(authenticationException, USER_METADATA_FETCH_EXCEPTION.getCode(), authenticationException.getStatus(), null);
        } catch (Exception exception) {
            log.error("Error occurred while retrieving user profile : ", exception);
            OAuth2AuthenticationException authenticationException = new OAuth2AuthenticationException(USER_METADATA_FETCH_EXCEPTION.getCode(), USER_METADATA_FETCH_EXCEPTION.getMessage() + " due to : " + exception.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
            return Utilities.handleErrorResponse(authenticationException, USER_METADATA_FETCH_EXCEPTION.getCode(), authenticationException.getStatus(), null);
        }

    }

    private UserMetadata fetchUserMetadata(String providerSubjectId, String identityProvider) throws OAuth2AuthenticationException {
        return userMetadataRepository.findByProviderSubjectIdAndIdentityProvider(providerSubjectId, identityProvider)
                .orElseThrow(() -> new OAuth2AuthenticationException(USER_METADATA_FETCH_EXCEPTION.getCode(), "User not found. Please check your credentials or register", HttpStatus.NOT_FOUND));
    }

    @PostMapping("/wallets")
    public ResponseEntity<ResponseWrapper<String>> createWallet(@RequestBody WalletRequestDto wallet, HttpSession httpSession) {
        try {
            ResponseWrapper<String> responseWrapper = new ResponseWrapper<>();
            responseWrapper.setResponse(walletService.createWallet((String) httpSession.getAttribute("userId"), wallet.getPin()));
            return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
        } catch (Exception exception) {
            log.error("Error occurred while creating user wallets : ", exception);
            return Utilities.handleErrorResponse(exception, USER_WALLET_CREATION_EXCEPTION.getCode(), HttpStatus.INTERNAL_SERVER_ERROR,MediaType.APPLICATION_JSON);
        }
    }

    @GetMapping("/wallets")
    public ResponseEntity<ResponseWrapper<List<String>>> getWallets(HttpSession httpSession) {
        try {
            ResponseWrapper<List<String>> responseWrapper = new ResponseWrapper<>();
            List<String> list = new ArrayList<>();
            list.addAll(walletService.getWallets((String) httpSession.getAttribute("userId")));
            responseWrapper.setResponse(list);
            return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
        } catch (Exception exception) {
            log.error("Error occurred while retrieving user wallets : ", exception);
            return Utilities.handleErrorResponse(exception, USER_WALLET_RETRIEVAL_EXCEPTION.getCode(), HttpStatus.INTERNAL_SERVER_ERROR,MediaType.APPLICATION_JSON);
        }
    }

    @PostMapping("/wallets/{walletId}")
    public ResponseEntity<ResponseWrapper<String>> getWallet(@PathVariable("walletId") String walletId, @RequestBody WalletRequestDto wallet, HttpSession httpSession) {
        try {
            // If wallet_key does not exist in the session, fetch it and set it in the session
            String walletKey = walletService.getWalletKey((String) httpSession.getAttribute("userId"), walletId, wallet.getPin());
            httpSession.setAttribute("wallet_key", walletKey);

            ResponseWrapper<String> responseWrapper = new ResponseWrapper<>();
            responseWrapper.setResponse(walletId);
            return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
        } catch (Exception exception) {
            log.error("Error occurred while retrieving user wallet ", exception);
            return Utilities.handleErrorResponse(exception, USER_WALLET_RETRIEVAL_EXCEPTION.getCode(), HttpStatus.INTERNAL_SERVER_ERROR,MediaType.APPLICATION_JSON);
        }
    }
}
