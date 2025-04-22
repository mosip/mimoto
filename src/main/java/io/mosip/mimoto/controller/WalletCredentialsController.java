package io.mosip.mimoto.controller;

import io.mosip.mimoto.constant.SwaggerLiteralConstants;
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
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
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

    @Operation(summary = "Download a Verifiable Credential", description = "This API allows the user to download a Verifiable Credential by providing the wallet ID and various query parameters such as issuer, credential type, storage expiry, and locale. The user's session is authenticated, and the requested credential is fetched and stored in the wallet. If successful, the API returns the Verifiable Credential details, otherwise, an appropriate error response is returned.", operationId = "downloadCredential", security = @SecurityRequirement(name = "SessionAuth"), parameters = {@Parameter(name = "walletId", in = ParameterIn.PATH, required = true, description = "Unique identifier of the wallet from which the credential will be downloaded", schema = @Schema(type = "string")), @Parameter(name = "issuer", in = ParameterIn.QUERY, required = false, description = "The identifier of the issuer of the credential", schema = @Schema(type = "string")), @Parameter(name = "credential", in = ParameterIn.QUERY, required = false, description = "The type of the credential to be downloaded", schema = @Schema(type = "string")), @Parameter(name = "vcStorageExpiryLimitInTimes", in = ParameterIn.QUERY, required = false, description = "The expiration limit for the Verifiable Credential storage", schema = @Schema(type = "string", defaultValue = "-1")), @Parameter(name = "locale", in = ParameterIn.QUERY, required = false, description = "The locale for the Verifiable Credential", schema = @Schema(type = "string"))}, requestBody = @RequestBody())
    @ApiResponse(responseCode = "200", description = "Verifiable Credential downloaded successfully", content = @Content(mediaType = "application/json", schema = @Schema(implementation = VerifiableCredentialResponseDTO.class)))
    @ApiResponse(responseCode = "400", description = "Bad Request - Invalid parameters or session", content = @Content(mediaType = "application/json", schema = @Schema(implementation = Error.class), examples = @ExampleObject(value = "{\"errorCode\": \"RESIDENT-APP-052\", \"errorMessage\": \"Exception occurred while fetching credential types\"}")))
    @ApiResponse(responseCode = "500", description = "Internal Server Error - Error occurred while fetching or storing the credential", content = @Content(mediaType = "application/json", schema = @Schema(implementation = Error.class), examples = @ExampleObject(value = "{\"errorCode\": \"RESIDENT-APP-052\", \"errorMessage\": \"Exception occurred while saving the credential\"}")))
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
            VerifiableCredentialResponseDTO credentialResponseDTO = walletCredentialService.fetchAndStoreCredential(issuerId, credentialType, response, credentialValidity, locale, walletId, base64EncodedWalletKey);

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

    @Operation(summary = "Fetch all credentials for a given wallet", description = "This API retrieves all credentials associated with the specified wallet. The wallet is identified using its unique wallet ID, and the credentials are returned based on the provided locale. The user's session is authenticated to ensure access to the wallet. If successful, the API returns a list of Verifiable Credentials. Otherwise, an appropriate error response is returned.", operationId = "fetchAllCredentialsForGivenWallet", security = @SecurityRequirement(name = "SessionAuth"), parameters = {@Parameter(name = "walletId", in = ParameterIn.PATH, required = true, description = "Unique identifier of the wallet for which credentials will be fetched", schema = @Schema(type = "string")), @Parameter(name = "locale", in = ParameterIn.QUERY, required = true, description = "The locale to be used for credential retrieval", schema = @Schema(type = "string"))})
    @ApiResponse(responseCode = "200", description = "Successfully retrieved all credentials for the wallet", content = @Content(mediaType = "application/json", schema = @Schema(implementation = VerifiableCredentialResponseDTO.class)))
    @ApiResponse(responseCode = "400", description = "Bad Request - Invalid wallet ID or missing parameters", content = @Content(mediaType = "application/json", schema = @Schema(implementation = Error.class), examples = @ExampleObject(value = "{\"errorCode\": \"RESIDENT-APP-053\", \"errorMessage\": \"Invalid wallet ID or missing parameters\"}")))
    @ApiResponse(responseCode = "500", description = "Internal Server Error - Error occurred while fetching credentials from the database", content = @Content(mediaType = "application/json", schema = @Schema(implementation = Error.class), examples = @ExampleObject(value = "{\"errorCode\": \"RESIDENT-APP-054\", \"errorMessage\": \"Error occurred while fetching credentials for wallet\"}")))
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

    @Operation(summary = "Fetch a specific Verifiable Credential", description = "This API retrieves a specific Verifiable Credential from the given wallet. The wallet and credential are identified by their respective IDs, and the locale parameter is used for localization. The action parameter determines whether the credential should be displayed inline or downloaded. The user's session is authenticated to ensure access to the wallet. If successful, the credential is returned as a PDF file. Otherwise, an appropriate error response is returned.", operationId = "getVerifiableCredential", security = @SecurityRequirement(name = "SessionAuth"), parameters = {@Parameter(name = "walletId", in = ParameterIn.PATH, required = true, description = "Unique identifier of the wallet from which the credential will be fetched", schema = @Schema(type = "string")), @Parameter(name = "credentialId", in = ParameterIn.PATH, required = true, description = "Unique identifier of the Verifiable Credential to be fetched", schema = @Schema(type = "string")), @Parameter(name = "locale", in = ParameterIn.QUERY, required = true, description = "The locale to be used for credential retrieval", schema = @Schema(type = "string")), @Parameter(name = "action", in = ParameterIn.QUERY, required = false, description = "Determines whether the credential is displayed inline or downloaded. Default is inline.", schema = @Schema(type = "string", defaultValue = "inline"))})
    @ApiResponse(responseCode = "200", description = "Successfully fetched the Verifiable Credential", content = @Content(mediaType = "application/pdf", examples = @ExampleObject(value = "{ \"credentialId\": \"123e4567-e89b-12d3-a456-426614174000\", \"fileName\": \"credential.pdf\" }")))
    @ApiResponse(responseCode = "400", description = "Bad Request - Invalid wallet ID, credential ID or missing parameters", content = @Content(mediaType = "application/json", schema = @Schema(implementation = Error.class), examples = @ExampleObject(value = "{\"errorCode\": \"RESIDENT-APP-053\", \"errorMessage\": \"Invalid wallet or credential ID\"}")))
    @ApiResponse(responseCode = "500", description = "Internal Server Error - Error occurred while fetching the Verifiable Credential", content = @Content(mediaType = "application/json", schema = @Schema(implementation = Error.class), examples = @ExampleObject(value = "{\"errorCode\": \"RESIDENT-APP-054\", \"errorMessage\": \"Error occurred while fetching the Verifiable Credential\"}")))
    @GetMapping("/{credentialId}")
    public ResponseEntity<InputStreamResource> getVerifiableCredential(@PathVariable("walletId") String walletId, @PathVariable("credentialId") String credentialId, @RequestParam("locale") String locale, @RequestParam(value = "action", defaultValue = "inline") String action, HttpSession httpSession) {
        try {
            log.info("Fetching credentialId: {} from walletId: {}", credentialId, walletId);

            WalletUtil.validateWalletId(httpSession, walletId);
            String base64EncodedWalletKey = WalletUtil.getSessionWalletKey(httpSession);

            WalletCredentialResponseDTO walletCredentialResponseDTO = walletCredentialService.fetchVerifiableCredential(walletId, credentialId, base64EncodedWalletKey, locale);

            String dispositionType = "download".equalsIgnoreCase(action) ? "attachment" : "inline";
            String contentDisposition = String.format("%s; filename=\"%s\"", dispositionType, walletCredentialResponseDTO.getFileName());

            return ResponseEntity.ok().header(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, HttpHeaders.CONTENT_DISPOSITION).header(HttpHeaders.CONTENT_DISPOSITION, contentDisposition).contentType(MediaType.APPLICATION_PDF).body(walletCredentialResponseDTO.getFileContentStream());

        } catch (DataAccessResourceFailureException exception) {
            log.error("Exception occurred while connecting to the database to fetch the Verifiable Credential:", exception);
            DatabaseConnectionException connectionException = new DatabaseConnectionException(DATABASE_CONNECTION_EXCEPTION.getCode(), DATABASE_CONNECTION_EXCEPTION.getMessage(), DatabaseEntity.VERIFIABLECREDENTIAL, DatabaseOperation.FETCHING, HttpStatus.INTERNAL_SERVER_ERROR);
            return Utilities.getErrorResponseEntityWithoutWrapper(connectionException, LOGIN_CREDENTIAL_DOWNLOAD_EXCEPTION.getCode(), connectionException.getStatus(), MediaType.APPLICATION_JSON);
        } catch (Exception exception) {
            log.error("Error occurred while fetching the Verifiable Credential : ", exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, CREDENTIAL_FETCH_EXCEPTION.getCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);
        }
    }
}