package io.mosip.mimoto.controller;

import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.VerifiableCredentialResponseDTO;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.model.DatabaseEntity;
import io.mosip.mimoto.model.DatabaseOperation;
import io.mosip.mimoto.service.WalletCredentialService;
import io.mosip.mimoto.util.CredentialUtilService;
import io.mosip.mimoto.util.Utilities;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static io.mosip.mimoto.exception.PlatformErrorMessages.*;

@Slf4j
@RestController
@RequestMapping(value = "/wallets/{walletId}/credentials")
public class WalletCredentialsController {

    private static final String SESSION_WALLET_KEY = "wallet_key";
    private static final String SESSION_WALLET_ID = "wallet_id";

    @Autowired
    private WalletCredentialService walletCredentialService;

    @Autowired
    private CredentialUtilService credentialUtilService;

    @PostMapping
    public ResponseEntity<?> downloadCredential(@PathVariable("walletId") String walletId, @RequestParam Map<String, String> params, HttpSession httpSession) {
        //TODO: remove this default value after the apitest is updated
        params.putIfAbsent("vcStorageExpiryLimitInTimes", "-1");

        try {
            validateWalletId(httpSession, walletId);
            String base64EncodedWalletKey = getSessionWalletKey(httpSession);

            String issuerId = params.get("issuer");
            String credentialType = params.get("credential");
            String credentialValidity = params.get("vcStorageExpiryLimitInTimes");
            String locale = params.get("locale");
            log.info("Initiated Token Call");
            TokenResponseDTO response = credentialUtilService.getTokenResponse(params, issuerId);

            log.info("Initiated call for fetching and storing Verifiable Credential in the database for walletId: {}", walletId);
            VerifiableCredentialResponseDTO credentialResponseDTO = walletCredentialService.fetchAndStoreCredential(
                    issuerId, credentialType, response, credentialValidity, locale, walletId, base64EncodedWalletKey);

            return ResponseEntity.status(HttpStatus.OK).body(credentialResponseDTO);
        } catch (ApiNotAccessibleException | IOException exception) {
            log.error("Exception occurred while fetching credential types ", exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, LOGIN_CREDENTIAL_DOWNLOAD_EXCEPTION.getCode(), HttpStatus.BAD_REQUEST, MediaType.APPLICATION_JSON);
        } catch (DataAccessResourceFailureException exception) {
            log.error("Exception occurred while connecting to the database to store downloaded Verifiable Credential:", exception);
            DatabaseConnectionException connectionException = new DatabaseConnectionException(DATABASE_CONNECTION_EXCEPTION.getCode(), DATABASE_CONNECTION_EXCEPTION.getMessage(), DatabaseEntity.VERIFIABLECREDENTIAL, DatabaseOperation.STORING, HttpStatus.INTERNAL_SERVER_ERROR);
            return Utilities.getErrorResponseEntityWithoutWrapper(connectionException, LOGIN_CREDENTIAL_DOWNLOAD_EXCEPTION.getCode(), connectionException.getStatus(), MediaType.APPLICATION_JSON);
        } catch (Exception exception) {
            log.error("Exception occurred while downloading or saving the Verifiable Credential:", exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, LOGIN_CREDENTIAL_DOWNLOAD_EXCEPTION.getCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);
        }
    }

    @GetMapping
    public ResponseEntity<?> fetchAllCredentialsForGivenWallet(@PathVariable("walletId") String walletId, @RequestParam("locale") String locale, HttpSession httpSession) {
        try {
            log.info("Fetching all credentials for walletId: {}", walletId);

            validateWalletId(httpSession, walletId);
            String base64EncodedWalletKey = getSessionWalletKey(httpSession);

            List<VerifiableCredentialResponseDTO> credentials = walletCredentialService.fetchAllCredentialsForWallet(walletId, base64EncodedWalletKey, locale);
            return ResponseEntity.status(HttpStatus.OK).body(credentials);
        } catch (DataAccessResourceFailureException exception) {
            log.error("Exception occurred while connecting to the database to fetch all credentials for walletId: {}", walletId, exception);
            DatabaseConnectionException connectionException = new DatabaseConnectionException(DATABASE_CONNECTION_EXCEPTION.getCode(), DATABASE_CONNECTION_EXCEPTION.getMessage(), DatabaseEntity.VERIFIABLECREDENTIAL, DatabaseOperation.FETCHING, HttpStatus.INTERNAL_SERVER_ERROR);
            return Utilities.getErrorResponseEntityWithoutWrapper(connectionException, DATABASE_CONNECTION_EXCEPTION.getCode(), connectionException.getStatus(), MediaType.APPLICATION_JSON);
        } catch (Exception exception) {
            log.error("Exception occurred while downloading or saving the Verifiable Credential:", exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, CREDENTIALS_FETCH_EXCEPTION.getCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);
        }
    }

    private String getSessionWalletKey(HttpSession session) {
        Object key = session.getAttribute(SESSION_WALLET_KEY);
        if (key == null) throw new RuntimeException("Wallet Key is missing in session");
        return key.toString();
    }

    private void validateWalletId(HttpSession session, String walletIdFromRequest) {
        Object sessionWalletId = session.getAttribute(SESSION_WALLET_ID);
        if (sessionWalletId == null) throw new RuntimeException("Wallet Id is missing in session");

        String walletIdInSession = sessionWalletId.toString();
        if (!walletIdInSession.equals(walletIdFromRequest)) {
            throw new RuntimeException("Invalid Wallet Id. Session and request Wallet Id do not match");
        }
    }
}