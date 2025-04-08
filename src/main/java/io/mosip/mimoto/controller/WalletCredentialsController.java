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
    @Autowired
    WalletCredentialService walletCredentialService;

    @Autowired
    CredentialUtilService credentialUtilService;

    @PostMapping
    public ResponseEntity<?> downloadCredential(@PathVariable("walletId") String walletId, @RequestParam Map<String, String> params, HttpSession httpSession) {
        //TODO: remove this default value after the apitest is updated
        params.putIfAbsent("vcStorageExpiryLimitInTimes", "-1");

        try {
            Object walletKeyObj = httpSession.getAttribute("wallet_key");
            if (walletKeyObj == null) {
                throw new RuntimeException("Wallet key is missing in session");
            }
            String base64EncodedWalletKey = walletKeyObj.toString();
            String issuerId = params.get("issuer");
            String credentialType = params.get("credential");
            String credentialValidity = params.get("vcStorageExpiryLimitInTimes");
            String locale = params.get("locale");
            log.info("Initiated Token Call");
            TokenResponseDTO response = credentialUtilService.getTokenResponse(params, issuerId);

            log.info("Initiated fetching Verifiable Credential and storing it in the database Call");
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
            Object walletKeyObj = httpSession.getAttribute("wallet_key");
            if (walletKeyObj == null) {
                throw new RuntimeException("Wallet key is missing in session");
            }

            String walletKey = walletKeyObj.toString();
            List<VerifiableCredentialResponseDTO> credentials = walletCredentialService.fetchAllCredentialsForWallet(walletId, walletKey, locale);
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
}