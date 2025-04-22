package io.mosip.mimoto.controller;

import io.mosip.kernel.core.crypto.exception.InvalidDataException;
import io.mosip.mimoto.constant.SwaggerExampleConstants;
import io.mosip.mimoto.constant.SwaggerLiteralConstants;
import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.WalletRequestDto;
import io.mosip.mimoto.dto.WalletResponseDto;
import io.mosip.mimoto.service.WalletService;
import io.mosip.mimoto.util.Utilities;
import io.mosip.mimoto.util.WalletValidator;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import io.swagger.v3.oas.annotations.responses.ApiResponse;

import java.util.List;

import static io.mosip.mimoto.exception.PlatformErrorMessages.USER_WALLET_CREATION_EXCEPTION;
import static io.mosip.mimoto.exception.PlatformErrorMessages.USER_WALLET_RETRIEVAL_EXCEPTION;

@Slf4j
@RestController
@RequestMapping(value = "/wallets")
@Tag(name = SwaggerLiteralConstants.WALLETS_NAME, description = SwaggerLiteralConstants.WALLETS_DESCRIPTION)
public class WalletsController {

    @Autowired
    private WalletService walletService;

    @Autowired
    private WalletValidator walletValidator;

    @Operation(summary = "Create a new wallet", description = "This API is secured using session-based authentication. The session ID is extracted from the Cookie header and used to retrieve session details from Redis for authentication. The user ID is then obtained from the session and along with the provided wallet name and PIN is used to create a new wallet in the database. If the wallet is created successfully, a unique identifier for the wallet is returned otherwise an appropriate error response is provided.", operationId = "createWallet", security = @SecurityRequirement(name = "SessionAuth"))
    @ApiResponse(responseCode = "200", description = "Wallet created successfully", content = @Content(mediaType = "application/json", schema = @Schema(type = "string", description = "Unique identifier of the Wallet stored in the database"), examples = @ExampleObject(name = "Success response", value = "d94a2e70-1234-4f2f-9eae-98765")))
    @ApiResponse(responseCode = "400", description = "Invalid wallet creation request", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(name = "Invalid request", value = "{\"errorCode\": \"RESIDENT-APP-050\", \"errorMessage\": \"Pin should be numeric with 4 or 6 digits.\"}")))
    @ApiResponse(responseCode = "500", description = "Internal server error while creating wallet", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(name = "Unexpected server error", value = "{\"errorCode\": \"RESIDENT-APP-050\", \"errorMessage\": \"An unexpected error occurred while creating the wallet\"}")))
    @PostMapping
    public ResponseEntity<String> createWallet(@RequestBody WalletRequestDto wallet, HttpSession httpSession) {
        try {
            walletValidator.validateWalletRequest(wallet);
            return ResponseEntity.status(HttpStatus.OK).body(walletService.createWallet((String) httpSession.getAttribute(SessionKeys.USER_ID), wallet.getWalletName(), wallet.getWalletPin()));
        } catch (IllegalArgumentException exception) {
            log.error("Error occurred while creating user wallets : ", exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, USER_WALLET_CREATION_EXCEPTION.getCode(), HttpStatus.BAD_REQUEST, MediaType.APPLICATION_JSON);
        } catch (Exception exception) {
            log.error("Error occurred while creating user wallets : ", exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, USER_WALLET_CREATION_EXCEPTION.getCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);
        }
    }

    @Operation(summary = "Retrieve all wallets for the user", description = "This API is secured using session-based authentication. Upon receiving a request, the session is first retrieved using the session ID extracted from the Cookie header to authenticate the user. Once authenticated, the user's ID is obtained from the session stored in Redis. Using this user ID, the API fetches all wallets associated with the user from the database and returns them. If an error occurs while retrieving the wallets, an appropriate error response is returned.", operationId = "getWallets", security = @SecurityRequirement(name = "SessionAuth"))
    @ApiResponse(responseCode = "200", description = "List of wallets retrieved successfully", content = @Content(mediaType = "application/json", array = @ArraySchema(schema = @Schema(implementation = WalletResponseDto.class)), examples = @ExampleObject(name = "Success response", value = SwaggerExampleConstants.FETCH_ALL_WALLETS_OF_USER_SUCCESS)))
    @ApiResponse(responseCode = "500", description = "Internal server error", content = @Content(mediaType = "application/json", schema = @Schema(implementation = ErrorDTO.class), examples = @ExampleObject(name = "Unexpected server error", value = "{\"errorCode\": \"RESIDENT-APP-051\", \"errorMessage\": \"An unexpected error occurred while retrieving user wallets\"}")))
    @GetMapping
    public ResponseEntity<List<WalletResponseDto>> getWallets(HttpSession httpSession) {
        try {
            List<WalletResponseDto> response = walletService.getWallets((String) httpSession.getAttribute(SessionKeys.USER_ID));

            return ResponseEntity.status(HttpStatus.OK).body(response);
        } catch (Exception exception) {
            log.error("Error occurred while retrieving user wallets : ", exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, USER_WALLET_RETRIEVAL_EXCEPTION.getCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);
        }
    }

    @Operation(summary = "Unlock an existing Wallet", description = "This API is secured using session-based authentication. Upon receiving a request, the session is first retrieved using the session ID extracted from the Cookie header to authenticate the user. Once authenticated, the user's ID is obtained from the session stored in Redis. Using this user ID along with the provided wallet ID and PIN, the corresponding wallet key is fetched and stored in the session. If successful, the API returns a response containing the wallet ID; otherwise, an appropriate error response is returned.", operationId = "unlockWallet", security = @SecurityRequirement(name = "SessionAuth"), parameters = {@Parameter(name = "walletId", in = ParameterIn.PATH, required = true, description = "Unique identifier of the wallet to be unlocked", schema = @Schema(type = "string"))}, requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(required = true, content = @Content(mediaType = "application/json", schema = @Schema(implementation = WalletRequestDto.class))))
    @ApiResponse(responseCode = "200", description = "Wallet unlocked successfully", content = @Content(mediaType = "application/json", schema = @Schema(implementation = WalletResponseDto.class), examples = @ExampleObject(value = "{\"walletId\": \"123e4567-e89b-12d3-a456-426614174000\"}")))
    @ApiResponse(responseCode = "401", description = "Unauthorized", content = @Content(mediaType = "application/json", schema = @Schema(implementation = Error.class), examples = @ExampleObject(value = "{\"errorCode\": \"RESIDENT-APP-051\", \"errorMessage\": \"Exception occurred due to an incorrect pin to unlock the wallet\"}")))
    @ApiResponse(responseCode = "500", description = "Internal Server Error", content = @Content(mediaType = "application/json", schema = @Schema(implementation = Error.class), examples = @ExampleObject(value = "{\"errorCode\": \"RESIDENT-APP-051\", \"errorMessage\": \"An unexpected error occurred while retrieving the wallet details\"}")))
    @PostMapping("/{walletId}/unlock")
    public ResponseEntity<WalletResponseDto> unlockWallet(@PathVariable("walletId") String walletId, @RequestBody WalletRequestDto wallet, HttpSession httpSession) {
        try {
            // If wallet_key does not exist in the session, fetch it and set it in the session
            String walletKey = walletService.getWalletKey((String) httpSession.getAttribute(SessionKeys.USER_ID), walletId, wallet.getWalletPin());

            if (null != walletKey) {
                httpSession.setAttribute(SessionKeys.WALLET_KEY, walletKey);
                httpSession.setAttribute(SessionKeys.WALLET_ID, walletId);
                WalletResponseDto response = new WalletResponseDto(walletId);
                return ResponseEntity.status(HttpStatus.OK).body(response);
            }
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
        } catch (InvalidDataException exception) {
            log.error("Incorrect pin to unlock the wallet ", exception);
            return Utilities.getErrorResponseEntityFromPlatformErrorMessage(USER_WALLET_RETRIEVAL_EXCEPTION, HttpStatus.UNAUTHORIZED, MediaType.APPLICATION_JSON);
        } catch (Exception exception) {
            log.error("Error occurred while retrieving user wallet ", exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, USER_WALLET_RETRIEVAL_EXCEPTION.getCode(), HttpStatus.INTERNAL_SERVER_ERROR, MediaType.APPLICATION_JSON);
        }
    }
}
