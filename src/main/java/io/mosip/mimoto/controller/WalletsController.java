package io.mosip.mimoto.controller;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.constant.SwaggerExampleConstants;
import io.mosip.mimoto.constant.SwaggerLiteralConstants;
import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.WalletRequestDto;
import io.mosip.mimoto.dto.WalletResponseDto;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.service.WalletService;
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
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;


/**
 * REST controller for managing wallets.
 */
@Slf4j
@RestController
@RequestMapping(value = "/wallets")
@Tag(name = SwaggerLiteralConstants.WALLETS_NAME, description = SwaggerLiteralConstants.WALLETS_DESCRIPTION)
public class WalletsController {

    private final WalletService walletService;

    @Autowired
    public WalletsController(WalletService walletService) {
        this.walletService = walletService;
    }

    /**
     * Creates a new wallet for a user.
     *
     * @param wallet The wallet creation request containing name and PIN.
     * @param httpSession The HTTP session containing user details.
     * @return The unique identifier of the created wallet.
     * @throws InvalidRequestException If the request is invalid.
     */
    @Operation(summary = "Create a new wallet", description = "This API is secured using session-based authentication. The session ID is extracted from the Cookie header and used to retrieve session details from Redis for authentication. The user ID is obtained from the session and used with the provided wallet name and PIN to create a new wallet in the database. If successful, a unique identifier for the wallet is returned; otherwise, an appropriate error response is provided.", operationId = "createWallet", security = @SecurityRequirement(name = "SessionAuth"))
    @ApiResponse(responseCode = "200", description = "Wallet created successfully", content = @Content(mediaType = "application/json", schema = @Schema(type = "string", description = "Unique identifier of the Wallet stored in the database"), examples = @ExampleObject(name = "Success response", value = "d94a2e70-1234-4f2f-9eae-98765")))
    @ApiResponse(responseCode = "400", description = "Invalid wallet creation request", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = {@ExampleObject(name = "User ID is not present in session", value = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"User ID not found in session\"}"), @ExampleObject(name = "Invalid User ID", value = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"User ID cannot be null or empty\"}"), @ExampleObject(name = "Invalid Wallet name", value = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"Wallet name must be alphanumeric with allowed special characters\"}"), @ExampleObject(name = "Invalid Wallet Pin", value = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"PIN must be numeric with 4 or 6 digits\"}")}))
    @ApiResponse(responseCode = "500", description = "Internal server error while creating wallet", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(name = "Unexpected Server Error", value = "{\"errorCode\": \"internal_server_error\", \"errorMessage\": \"We are unable to process request now\"}")))
    @ApiResponse(responseCode = "503", description = "Service unavailable", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(name = "Database connection failure", value = "{\"errorCode\": \"database_unavailable\", \"errorMessage\": \"Failed to connect to the database\"}")))
    @PostMapping
    public ResponseEntity<String> createWallet(
            @RequestBody @Valid WalletRequestDto wallet,
            HttpSession httpSession) throws InvalidRequestException {
        String userId = (String) httpSession.getAttribute(SessionKeys.USER_ID);
        if (userId == null) {
            log.error("User ID not found in session");
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST.getErrorCode(), "User ID not found in session");
        }
        log.info("Creating wallet for user: {}, name: {}", userId, wallet.getWalletName());
        String walletId = walletService.createWallet(userId, wallet.getWalletName(), wallet.getWalletPin());
        return ResponseEntity.status(HttpStatus.OK).body(walletId);
    }

    /**
     * Retrieves all wallets for the authenticated user.
     *
     * @param httpSession The HTTP session containing user details.
     * @return List of wallet details.
     * @throws InvalidRequestException If the request fails.
     */
    @Operation(summary = "Retrieve all wallets for the user", description = "This API is secured using session-based authentication. The session ID is extracted from the Cookie header to authenticate the user. The user's ID is obtained from the session stored in Redis, and all wallets associated with the user are fetched from the database. If successful, the list of wallets is returned; otherwise, an appropriate error response is returned.", operationId = "getWallets", security = @SecurityRequirement(name = "SessionAuth"))
    @ApiResponse(responseCode = "200", description = "List of wallets retrieved successfully", content = @Content(mediaType = "application/json", array = @ArraySchema(schema = @Schema(implementation = WalletResponseDto.class)), examples = @ExampleObject(name = "Success response", value = "[{\"walletId\": \"123e4567-e89b-12d3-a456-426614174000\"}, {\"walletId\": \"223e4567-e89b-12d3-a456-426614174001\"}]")))
    @ApiResponse(responseCode = "400", description = "Invalid Wallets fetching request", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(name = "User ID is not present in session", value = "{\"errorCode\": \"invalid_request\", \"errorMessage\": \"User ID not found in session\"}")))
    @ApiResponse(responseCode = "500", description = "Internal server error", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(name = "Unexpected Server Error", value = "{\"errorCode\": \"internal_server_error\", \"errorMessage\": \"We are unable to process request now\"}")))
    @ApiResponse(responseCode = "503", description = "Service unavailable", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(name = "Database connection failure", value = "{\"errorCode\": \"database_unavailable\", \"errorMessage\": \"Failed to connect to the database\"}")))
    @GetMapping
    public ResponseEntity<List<WalletResponseDto>> getWallets(HttpSession httpSession) throws InvalidRequestException {
        String userId = (String) httpSession.getAttribute(SessionKeys.USER_ID);
        if (userId == null) {
            log.error("User ID not found in session");
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST.getErrorCode(), "User ID not found in session");
        }
        log.info("Retrieving wallets for user: {}", userId);
        List<WalletResponseDto> response = walletService.getWallets(userId);
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }

    /**
     * Unlocks an existing wallet by retrieving its key and storing it in the session.
     *
     * @param walletId The unique identifier of the wallet.
     * @param wallet The request containing the wallet PIN.
     * @param httpSession The HTTP session containing user details.
     * @return The wallet details if unlocked successfully.
     * @throws InvalidRequestException If the wallet or PIN is invalid.
     */
    @Operation(summary = "Unlock an existing Wallet", description = "This API is secured using session-based authentication. The session ID is extracted from the Cookie header to authenticate the user. The user's ID is obtained from the session, and the provided wallet ID and PIN are used to fetch the wallet key, which is stored in the session. If successful, the wallet ID is returned; otherwise, an appropriate error response is returned.", operationId = "unlockWallet", security = @SecurityRequirement(name = "SessionAuth"), parameters = {@Parameter(name = "walletId", in = ParameterIn.PATH, required = true, description = "Unique identifier of the wallet to be unlocked", schema = @Schema(type = "string"))}, requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(required = true, content = @Content(mediaType = "application/json", schema = @Schema(implementation = WalletRequestDto.class))))
    @ApiResponse(responseCode = "200", description = "Wallet unlocked successfully", content = @Content(mediaType = "application/json", schema = @Schema(implementation = WalletResponseDto.class), examples = @ExampleObject(value = "{\"walletId\": \"123e4567-e89b-12d3-a456-426614174000\"}")))
    @ApiResponse(responseCode = "400", description = "Invalid wallet ID or PIN", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(value = "{\"errorCode\": \"RESIDENT-APP-051\", \"errorMessage\": \"Exception occurred due to an incorrect pin to unlock the wallet\"}")))
    @ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(value = "{\"errorCode\": \"RESIDENT-APP-051\", \"errorMessage\": \"Exception occurred due to an incorrect pin to unlock the wallet\"}")))
    @ApiResponse(responseCode = "500", description = "Internal server error", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(name = "Unexpected server error", value = "{\"errorCode\": \"RESIDENT-APP-051\", \"errorMessage\": \"An unexpected error occurred while retrieving the wallet details\"}")))
    @ApiResponse(responseCode = "503", description = "Service unavailable", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(value = "{\"errorCode\": \"database_unavailable\", \"errorMessage\": \"Failed to connect to the database\"}")))
    @PostMapping("/{walletId}/unlock")
    public ResponseEntity<WalletResponseDto> unlockWallet(
            @PathVariable("walletId") @NotBlank(message = "Wallet ID cannot be blank") String walletId,
            @RequestBody @Valid WalletRequestDto wallet,
            HttpSession httpSession) throws InvalidRequestException {
        String userId = (String) httpSession.getAttribute(SessionKeys.USER_ID);
        if (userId == null) {
            log.error("User ID not found in session");
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST.getErrorCode(), "User ID not found in session");
        }
        log.info("Unlocking wallet: {} for user: {}", walletId, userId);
        String walletKey = walletService.getWalletKey(userId, walletId, wallet.getWalletPin());
        httpSession.setAttribute(SessionKeys.WALLET_KEY, walletKey);
        httpSession.setAttribute(SessionKeys.WALLET_ID, walletId);
        WalletResponseDto response = WalletResponseDto.builder().walletId(walletId).build();
        return ResponseEntity.status(HttpStatus.OK).body(response);
    }
}
