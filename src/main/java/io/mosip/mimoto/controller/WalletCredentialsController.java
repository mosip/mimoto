package io.mosip.mimoto.controller;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.constant.SwaggerLiteralConstants;
import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.mimoto.VerifiableCredentialResponseDTO;
import io.mosip.mimoto.dto.resident.WalletCredentialResponseDTO;
import io.mosip.mimoto.exception.*;
import io.mosip.mimoto.service.WalletCredentialService;
import io.mosip.mimoto.util.CredentialUtilService;
import io.mosip.mimoto.util.Utilities;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static io.mosip.mimoto.exception.ErrorConstants.CREDENTIAL_DOWNLOAD_EXCEPTION;

/**
 * REST controller for managing wallet credentials.
 */
@Slf4j
@RestController
@RequestMapping(value = "/wallets/{walletId}/credentials")
@Tag(name = SwaggerLiteralConstants.WALLET_CREDENTIALS_NAME, description = SwaggerLiteralConstants.WALLET_CREDENTIALS_DESCRIPTION)
public class WalletCredentialsController {

    private final WalletCredentialService walletCredentialService;
    private final CredentialUtilService credentialUtilService;

    @Autowired
    public WalletCredentialsController(WalletCredentialService walletCredentialService,
                                       CredentialUtilService credentialUtilService) {
        this.walletCredentialService = walletCredentialService;
        this.credentialUtilService = credentialUtilService;
    }

    /**
     * Downloads and stores a Verifiable Credential in the specified wallet.
     *
     * @param walletId The unique identifier of the wallet.
     * @param params Query parameters including issuer, credential type, storage expiry, and locale.
     * @param httpSession The HTTP session containing wallet key and ID.
     * @return The stored Verifiable Credential details.
     * @throws InvalidRequestException If input parameters or session are invalid.
     */
    @Operation(summary = "Download a Verifiable Credential", description = "This API allows downloading a Verifiable Credential by providing the wallet ID and query parameters such as issuer, credential type, storage expiry, and locale. The user's session is authenticated, and the credential is fetched and stored in the wallet. If successful, the Verifiable Credential details are returned; otherwise, an appropriate error response is provided.", operationId = "downloadCredential", security = @SecurityRequirement(name = "SessionAuth"), parameters = {
            @Parameter(name = "walletId", in = ParameterIn.PATH, required = true, description = "Unique identifier of the wallet", schema = @Schema(type = "string")),
            @Parameter(name = "issuer", in = ParameterIn.QUERY, required = true, description = "The identifier of the issuer", schema = @Schema(type = "string")),
            @Parameter(name = "credential", in = ParameterIn.QUERY, required = true, description = "The type of the credential", schema = @Schema(type = "string")),
            @Parameter(name = "vcStorageExpiryLimitInTimes", in = ParameterIn.QUERY, required = false, description = "The expiration limit for the Verifiable Credential storage", schema = @Schema(type = "string", defaultValue = "-1")),
            @Parameter(name = "locale", in = ParameterIn.QUERY, required = false, description = "The locale for the Verifiable Credential", schema = @Schema(type = "string", defaultValue = "en"))
    })
    @ApiResponse(responseCode = "200", description = "Verifiable Credential downloaded successfully", content = @Content(mediaType = "application/json", schema = @Schema(implementation = VerifiableCredentialResponseDTO.class)))
    @ApiResponse(responseCode = "400", description = "Bad Request - Invalid parameters or session", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(value = "{\"errorCode\": \"RESIDENT-APP-052\", \"errorMessage\": \"Invalid wallet ID or missing parameters\"}")))
    @ApiResponse(responseCode = "500", description = "Internal Server Error - Error occurred while processing credential", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(value = "{\"errorCode\": \"RESIDENT-APP-054\", \"errorMessage\": \"Error occurred while saving the credential\"}")))
    @ApiResponse(responseCode = "503", description = "Service Unavailable - Error occurred while fetching token", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(value = "{\"errorCode\": \"RESIDENT-APP-052\", \"errorMessage\": \"Failed to fetch token response\"}")))
    @PostMapping
    public ResponseEntity<VerifiableCredentialResponseDTO> downloadCredential(
            @PathVariable("walletId") @NotBlank(message = "Wallet ID cannot be blank") String walletId,
            @RequestParam Map<String, String> params,
            HttpSession httpSession) throws InvalidRequestException {
        params.putIfAbsent("vcStorageExpiryLimitInTimes", "-1");
        params.putIfAbsent("locale", "en");

        String storedWalletId = (String) httpSession.getAttribute(SessionKeys.WALLET_ID);
        if (!walletId.equals(storedWalletId)) {
            log.error("Wallet ID mismatch: provided {}, stored {}", walletId, storedWalletId);
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST.getErrorCode(), "Wallet ID mismatch");
        }
        String base64EncodedWalletKey = (String) httpSession.getAttribute(SessionKeys.WALLET_KEY);
        if (base64EncodedWalletKey == null) {
            log.error("Wallet key not found in session");
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST.getErrorCode(), "Wallet key not found in session");
        }

        String issuerId = params.get("issuer");
        String credentialType = params.get("credential");
        String credentialValidity = params.get("vcStorageExpiryLimitInTimes");
        String locale = params.get("locale");

        if (issuerId == null || issuerId.isBlank() || credentialType == null || credentialType.isBlank()) {
            log.error("Missing required parameters: issuer or credential");
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST.getErrorCode(), "Issuer and credential type are required");
        }

        log.info("Initiating token call for issuer: {}", issuerId);
        TokenResponseDTO tokenResponse;
        try {
            tokenResponse = credentialUtilService.getTokenResponse(params, issuerId);
        } catch (ApiNotAccessibleException | IOException | AuthorizationServerWellknownResponseException |
                 InvalidWellknownResponseException e) {
            log.error("Error fetching token response for issuer: {}", issuerId, e);
            return Utilities.getErrorResponseEntityFromPlatformErrorMessage(
                    CREDENTIAL_DOWNLOAD_EXCEPTION, HttpStatus.SERVICE_UNAVAILABLE, MediaType.APPLICATION_JSON);
        }

        log.info("Fetching and storing Verifiable Credential for walletId: {}", walletId);
        VerifiableCredentialResponseDTO credentialResponseDTO = null;
        try {
            credentialResponseDTO = walletCredentialService.fetchAndStoreCredential(
                    issuerId, credentialType, tokenResponse, credentialValidity, locale, walletId, base64EncodedWalletKey);
        } catch (ExternalServiceUnavailableException e) {
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    e, e.getErrorCode(), HttpStatus.SERVICE_UNAVAILABLE, MediaType.APPLICATION_JSON);
        }  catch (CredentialProcessingException e) {
            log.error("Error processing credential download for walletId: {} ", walletId, e);
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    e, e.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);
        }
        return ResponseEntity.status(HttpStatus.OK).body(credentialResponseDTO);
    }

    /**
     * Fetches all credentials for a given wallet.
     *
     * @param walletId The unique identifier of the wallet.
     * @param locale The locale for credential retrieval.
     * @param httpSession The HTTP session containing wallet key and ID.
     * @return List of Verifiable Credential details.
     * @throws InvalidRequestException If session or wallet ID is invalid.
     */
    @Operation(summary = "Fetch all credentials for a given wallet", description = "This API retrieves all credentials associated with the specified wallet, identified by its unique wallet ID. The credentials are returned based on the provided locale. The user's session is authenticated to ensure access to the wallet. If successful, a list of Verifiable Credentials is returned; otherwise, an appropriate error response is returned.", operationId = "fetchAllCredentialsForGivenWallet", security = @SecurityRequirement(name = "SessionAuth"), parameters = {
            @Parameter(name = "walletId", in = ParameterIn.PATH, required = true, description = "Unique identifier of the wallet", schema = @Schema(type = "string")),
            @Parameter(name = "locale", in = ParameterIn.QUERY, required = false, description = "The locale for credential retrieval", schema = @Schema(type = "string", defaultValue = "en"))
    })
    @ApiResponse(responseCode = "200", description = "Successfully retrieved all credentials for the wallet", content = @Content(mediaType = "application/json", array = @ArraySchema(schema = @Schema(implementation = VerifiableCredentialResponseDTO.class))))
    @ApiResponse(responseCode = "400", description = "Bad Request - Invalid wallet ID or session", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(value = "{\"errorCode\": \"RESIDENT-APP-053\", \"errorMessage\": \"Invalid wallet ID or missing parameters\"}")))
    @ApiResponse(responseCode = "500", description = "Internal Server Error - Error occurred while fetching credentials", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(value = "{\"errorCode\": \"RESIDENT-APP-054\", \"errorMessage\": \"Error occurred while fetching credentials for wallet\"}")))
    @GetMapping
    public ResponseEntity<List<VerifiableCredentialResponseDTO>> fetchAllCredentialsForGivenWallet(
            @PathVariable("walletId") @NotBlank(message = "Wallet ID cannot be blank") String walletId,
            @RequestParam(value = "locale", defaultValue = "en") @Pattern(regexp = "^[a-z]{2}$", message = "Locale must be a 2-letter code") String locale,
            HttpSession httpSession) throws InvalidRequestException {
        String storedWalletId = (String) httpSession.getAttribute(SessionKeys.WALLET_ID);
        if (!walletId.equals(storedWalletId)) {
            log.error("Wallet ID mismatch: provided {}, stored {}", walletId, storedWalletId);
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST.getErrorCode(), "Wallet ID mismatch");
        }
        String base64EncodedWalletKey = (String) httpSession.getAttribute(SessionKeys.WALLET_KEY);
        if (base64EncodedWalletKey == null) {
            log.error("Wallet key not found in session");
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST.getErrorCode(), "Wallet key not found in session");
        }

        log.info("Fetching all credentials for walletId: {}", walletId);
        try {
            List<VerifiableCredentialResponseDTO> credentials = walletCredentialService.fetchAllCredentialsForWallet(
                walletId, base64EncodedWalletKey, locale);
            return ResponseEntity.status(HttpStatus.OK).body(credentials);
        } catch (CredentialProcessingException e) {
            log.error("Error processing credentials for walletId: {} ", walletId, e);
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    e, e.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);
        }

    }

    /**
     * Fetches a specific Verifiable Credential as a PDF.
     *
     * @param walletId The unique identifier of the wallet.
     * @param credentialId The unique identifier of the credential.
     * @param locale The locale for credential retrieval.
     * @param action The action (inline or download) for PDF display.
     * @param httpSession The HTTP session containing wallet key and ID.
     * @return The Verifiable Credential as a PDF stream.
     * @throws InvalidRequestException If session or parameters are invalid.
     */
    @Operation(summary = "Fetch a specific Verifiable Credential", description = "This API retrieves a specific Verifiable Credential from the given wallet, identified by wallet and credential IDs. The locale parameter is used for localization, and the action parameter determines whether the credential is displayed inline or downloaded as a PDF. The user's session is authenticated to ensure access. If successful, the credential is returned as a PDF file; otherwise, an appropriate error response is returned.", operationId = "getVerifiableCredential", security = @SecurityRequirement(name = "SessionAuth"), parameters = {
            @Parameter(name = "walletId", in = ParameterIn.PATH, required = true, description = "Unique identifier of the wallet", schema = @Schema(type = "string")),
            @Parameter(name = "credentialId", in = ParameterIn.PATH, required = true, description = "Unique identifier of the Verifiable Credential", schema = @Schema(type = "string")),
            @Parameter(name = "locale", in = ParameterIn.QUERY, required = false, description = "The locale for credential retrieval", schema = @Schema(type = "string", defaultValue = "en")),
            @Parameter(name = "action", in = ParameterIn.QUERY, required = false, description = "Determines whether the credential is displayed inline or downloaded. Default is inline.", schema = @Schema(type = "string", defaultValue = "inline"))
    })
    @ApiResponse(responseCode = "200", description = "Successfully fetched the Verifiable Credential", content = @Content(mediaType = "application/pdf", examples = @ExampleObject(value = "{ \"credentialId\": \"123e4567-e89b-12d3-a456-426614174000\", \"fileName\": \"credential.pdf\" }")))
    @ApiResponse(responseCode = "400", description = "Bad Request - Invalid wallet ID, credential ID, or session", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(value = "{\"errorCode\": \"RESIDENT-APP-053\", \"errorMessage\": \"Invalid wallet or credential ID\"}")))
    @ApiResponse(responseCode = "404", description = "Credential not found", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(value = "{\"errorCode\": \"RESIDENT-APP-053\", \"errorMessage\": \"Credential not found\"}")))
    @ApiResponse(responseCode = "500", description = "Internal Server Error - Error occurred while processing credential", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(value = "{\"errorCode\": \"RESIDENT-APP-054\", \"errorMessage\": \"Error occurred while fetching the Verifiable Credential\"}")))
    @GetMapping("/{credentialId}")
    public ResponseEntity<InputStreamResource> getVerifiableCredential(
            @PathVariable("walletId") @NotBlank(message = "Wallet ID cannot be blank") String walletId,
            @PathVariable("credentialId") @NotBlank(message = "Credential ID cannot be blank") String credentialId,
            @RequestParam(value = "locale", defaultValue = "en") @Pattern(regexp = "^[a-z]{2}$", message = "Locale must be a 2-letter code") String locale,
            @RequestParam(value = "action", defaultValue = "inline") @Pattern(regexp = "^(inline|download)$", message = "Action must be 'inline' or 'download'") String action,
            HttpSession httpSession) throws InvalidRequestException {
        String storedWalletId = (String) httpSession.getAttribute(SessionKeys.WALLET_ID);
        if (!walletId.equals(storedWalletId)) {
            log.error("Wallet ID mismatch: provided {}, stored {}", walletId, storedWalletId);
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST.getErrorCode(), "Wallet ID mismatch");
        }
        String base64EncodedWalletKey = (String) httpSession.getAttribute(SessionKeys.WALLET_KEY);
        if (base64EncodedWalletKey == null) {
            log.error("Wallet key not found in session");
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST.getErrorCode(), "Wallet key not found in session");
        }

        log.info("Fetching credentialId: {} from walletId: {}", credentialId, walletId);
        WalletCredentialResponseDTO walletCredentialResponseDTO = null;
        try {
            walletCredentialResponseDTO = walletCredentialService.fetchVerifiableCredential(
                    walletId, credentialId, base64EncodedWalletKey, locale);
        } catch (CredentialNotFoundException e) {
            log.error("Credential not found for walletId: {} and credentialId: {}", walletId, credentialId, e);
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    e, e.getErrorCode(), HttpStatus.NOT_FOUND, MediaType.APPLICATION_JSON);
        } catch (CredentialProcessingException e) {
            log.error("Error processing credential for walletId: {} and credentialId: {}", walletId, credentialId, e);
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    e, e.getErrorCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);
        }

            String dispositionType = "download".equalsIgnoreCase(action) ? "attachment" : "inline";
        String contentDisposition = String.format("%s; filename=\"%s\"", dispositionType, walletCredentialResponseDTO.getFileName());

        return ResponseEntity.ok()
                .header(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, HttpHeaders.CONTENT_DISPOSITION)
                .header(HttpHeaders.CONTENT_DISPOSITION, contentDisposition)
                .contentType(MediaType.APPLICATION_PDF)
                .body(walletCredentialResponseDTO.getFileContentStream());
    }
}