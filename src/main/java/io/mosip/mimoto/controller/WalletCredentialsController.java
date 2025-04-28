package io.mosip.mimoto.controller;

import io.mosip.mimoto.constant.SwaggerLiteralConstants;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.VerifiableCredentialResponseDTO;
import io.mosip.mimoto.dto.resident.WalletCredentialResponseDTO;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.exception.CredentialNotFoundException;
import io.mosip.mimoto.exception.UnauthorizedWalletAccessException;
import io.mosip.mimoto.model.DatabaseEntity;
import io.mosip.mimoto.model.DatabaseOperation;
import io.mosip.mimoto.service.WalletCredentialService;
import io.mosip.mimoto.util.CredentialUtilService;
import io.mosip.mimoto.util.Utilities;
import io.mosip.mimoto.util.WalletUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@Tag(name = SwaggerLiteralConstants.WALLET_CREDENTIALS_NAME, description = SwaggerLiteralConstants.WALLET_CREDENTIALS_DESCRIPTION)
public class WalletCredentialsController {
    @Autowired
    private WalletCredentialService walletCredentialService;

    @Autowired
    private CredentialUtilService credentialUtilService;

    @Operation(summary = SwaggerLiteralConstants.WALLET_CREDENTIALS_DOWNLOAD_SUMMARY, description = SwaggerLiteralConstants.WALLET_CREDENTIALS_DOWNLOAD_DESCRIPTION)
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Credential successfully downloaded"),
            @ApiResponse(responseCode = "400", description = "Bad request"),
            @ApiResponse(responseCode = "500", description = "Internal server error", content = {@Content(mediaType = "application/json")})})

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

    @Operation(summary = SwaggerLiteralConstants.WALLET_CREDENTIALS_FETCH_ALL_SUMMARY, description = SwaggerLiteralConstants.WALLET_CREDENTIALS_FETCH_ALL_DESCRIPTION)
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Credentials successfully retrieved"),
            @ApiResponse(responseCode = "500", description = "Internal server error", content = {@Content(mediaType = "application/json")})})

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
    /**
     * Deletes a credential by its ID
     *
     * @param walletId The ID of the wallet that owns the credential
     * @param credentialId The ID of the credential to delete
     * @return ResponseEntity with HTTP status 200 if successful, 404 if credential not found, or 500 for other errors
     */
    @Operation(summary = SwaggerLiteralConstants.WALLET_CREDENTIALS_DELETE_SUMMARY, description = SwaggerLiteralConstants.WALLET_CREDENTIALS_DELETE_DESCRIPTION)
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Credential successfully deleted"),
            @ApiResponse(responseCode = "403", description = "Unauthorized access to wallet"),
            @ApiResponse(responseCode = "404", description = "Credential not found"),
            @ApiResponse(responseCode = "500", description = "Internal server error", content = {@Content(mediaType = "application/json")})})
    @DeleteMapping("/{credentialId}")
    public ResponseEntity<?> deleteCredential(@PathVariable("walletId") String walletId,
                                              @PathVariable("credentialId") String credentialId,
                                              HttpSession httpSession) {
        try {
            log.info("Deleting credential with ID: {} for walletId: {}", credentialId, walletId);

            // Validate that the wallet ID in the request matches the one in the session
            Object sessionWalletId = httpSession.getAttribute("wallet_id");
            if (sessionWalletId == null) {
                log.error("Wallet ID is missing in session");
                throw new UnauthorizedWalletAccessException("Wallet ID is missing in session");
            }

            if (!sessionWalletId.toString().equals(walletId)) {
                log.error("Wallet ID in request ({}) does not match wallet ID in session ({})",
                        walletId, sessionWalletId.toString());
                throw new UnauthorizedWalletAccessException("Unauthorized access to wallet");
            }

            // Delete the credential
            walletCredentialService.deleteCredential(credentialId, walletId);
            return ResponseEntity.status(HttpStatus.OK).build();

        } catch (UnauthorizedWalletAccessException exception) {
            log.error("Unauthorized access to wallet: {}", exception.getMessage());
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    exception,
                    exception.getErrorCode(),
                    HttpStatus.FORBIDDEN,
                    MediaType.APPLICATION_JSON);
        } catch (CredentialNotFoundException exception) {
            log.error("Credential not found: {}", exception.getMessage());
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    exception,
                    exception.getErrorCode(),
                    HttpStatus.NOT_FOUND,
                    MediaType.APPLICATION_JSON);
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