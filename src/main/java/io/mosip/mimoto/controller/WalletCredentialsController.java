package io.mosip.mimoto.controller;

import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.VerifiableCredentialResponseDTO;
import io.mosip.mimoto.dto.resident.WalletCredentialResponseDTO;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.model.DatabaseEntity;
import io.mosip.mimoto.model.DatabaseOperation;
import io.mosip.mimoto.service.WalletCredentialService;
import io.mosip.mimoto.util.CredentialUtilService;
import io.mosip.mimoto.util.Utilities;
import io.mosip.mimoto.util.WalletUtil;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.InputStreamResource;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.http.HttpHeaders;
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
    private WalletCredentialService walletCredentialService;

    @Autowired
    private CredentialUtilService credentialUtilService;

    @PostMapping
    public ResponseEntity<VerifiableCredentialResponseDTO> downloadCredential(@PathVariable("walletId") String walletId, @RequestParam Map<String, String> params, HttpSession httpSession) {
        //TODO: remove this default value after the apitest is updated
        params.putIfAbsent("vcStorageExpiryLimitInTimes", "-1");

        try {
            WalletUtil.validateWalletId(httpSession, walletId);
            String base64EncodedWalletKey = WalletUtil.getSessionWalletKey(httpSession);

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
    public ResponseEntity<List<VerifiableCredentialResponseDTO>> fetchAllCredentialsForGivenWallet(@PathVariable("walletId") String walletId, @RequestParam("locale") String locale, HttpSession httpSession) {
        try {
            log.info("Fetching all credentials for walletId: {}", walletId);

            WalletUtil.validateWalletId(httpSession, walletId);
            String base64EncodedWalletKey = WalletUtil.getSessionWalletKey(httpSession);

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

    @GetMapping("/{credentialId}")
    public ResponseEntity<InputStreamResource> getVerifiableCredential(@PathVariable("walletId") String walletId, @PathVariable("credentialId") String credentialId, @RequestParam("locale") String locale, @RequestParam(value = "action", defaultValue = "inline") String action, HttpSession httpSession) {
        try {
            log.info("Fetching credentialId: {} from walletId: {}", credentialId, walletId);

            WalletUtil.validateWalletId(httpSession, walletId);
            String base64EncodedWalletKey = WalletUtil.getSessionWalletKey(httpSession);

            WalletCredentialResponseDTO walletCredentialResponseDTO = walletCredentialService.fetchVerifiableCredential(walletId,
                    credentialId, base64EncodedWalletKey, locale);

            String dispositionType = "download".equalsIgnoreCase(action) ? "attachment" : "inline";
            String contentDisposition = String.format("%s; filename=\"%s\"",
                    dispositionType, walletCredentialResponseDTO.getFileName());

            return ResponseEntity.ok()
                    .header(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, HttpHeaders.CONTENT_DISPOSITION)
                    .header(HttpHeaders.CONTENT_DISPOSITION, contentDisposition)
                    .contentType(MediaType.APPLICATION_PDF)
                    .body(walletCredentialResponseDTO.getFileContentStream());

        } catch (DataAccessResourceFailureException exception) {
            log.error("Exception occurred while connecting to the database to fetch the Verifiable Credential:", exception);
            DatabaseConnectionException connectionException = new DatabaseConnectionException(DATABASE_CONNECTION_EXCEPTION.getCode(), DATABASE_CONNECTION_EXCEPTION.getMessage(), DatabaseEntity.VERIFIABLECREDENTIAL, DatabaseOperation.FETCHING, HttpStatus.INTERNAL_SERVER_ERROR);
            return Utilities.getErrorResponseEntityWithoutWrapper(connectionException, LOGIN_CREDENTIAL_DOWNLOAD_EXCEPTION.getCode(), connectionException.getStatus(), MediaType.APPLICATION_JSON);
        } catch (Exception exception) {
            log.error("Error occurred while fetching the Verifiable Credential : ", exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, CREDENTIAL_FETCH_EXCEPTION.getCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);
        }
    }
    @DeleteMapping("/{credentialId}")
    public ResponseEntity<?> deleteCredential(@PathVariable("walletId") String walletId,
                                              @PathVariable("credentialId") String credentialId) {
        try {
            log.info("Deleting credential with ID: {} for walletId: {}", credentialId, walletId);

            boolean deleted = walletCredentialService.deleteCredential(credentialId, walletId);

            if (deleted) {
                return ResponseEntity.status(HttpStatus.OK).build();
            } else {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
            }
        } catch (DataAccessResourceFailureException exception) {
            log.error("Exception occurred while connecting to the database to delete credential with ID: {} for walletId: {}",
                    credentialId, walletId, exception);
            DatabaseConnectionException connectionException = new DatabaseConnectionException(
                    DATABASE_CONNECTION_EXCEPTION.getCode(),
                    DATABASE_CONNECTION_EXCEPTION.getMessage(),
                    DatabaseEntity.VERIFIABLECREDENTIAL,
                    DatabaseOperation.DELETING,
                    HttpStatus.INTERNAL_SERVER_ERROR);
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    connectionException,
                    DATABASE_CONNECTION_EXCEPTION.getCode(),
                    connectionException.getStatus(),
                    MediaType.APPLICATION_JSON);
        } catch (Exception exception) {
            log.error("Exception occurred while deleting credential with ID: {} for walletId: {}",
                    credentialId, walletId, exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    exception,
                    CREDENTIAL_DELETE_EXCEPTION.getCode(),
                    HttpStatus.INTERNAL_SERVER_ERROR,
                    MediaType.APPLICATION_JSON);
        }
    }
}