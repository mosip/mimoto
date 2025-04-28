package io.mosip.mimoto.controller;

import io.mosip.kernel.core.crypto.exception.InvalidDataException;
import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.exception.UnauthorizedWalletAccessException;
import io.mosip.mimoto.dto.WalletRequestDto;
import io.mosip.mimoto.dto.WalletResponseDto;
import io.mosip.mimoto.service.WalletService;
import io.mosip.mimoto.util.Utilities;
import io.mosip.mimoto.util.WalletValidator;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

import static io.mosip.mimoto.exception.PlatformErrorMessages.USER_WALLET_CREATION_EXCEPTION;
import static io.mosip.mimoto.exception.PlatformErrorMessages.USER_WALLET_RETRIEVAL_EXCEPTION;

@Slf4j
@RestController
@RequestMapping(value = "/wallets")
public class WalletsController {


    @Autowired
    private WalletService walletService;

    @Autowired
    private WalletValidator walletValidator;

    @PostMapping
    public ResponseEntity<String> createWallet(@RequestBody WalletRequestDto wallet, HttpSession httpSession) {
        try {
            walletValidator.validateWalletRequest(wallet);
            return ResponseEntity.status(HttpStatus.OK).body(walletService.createWallet((String) httpSession.getAttribute(SessionKeys.USER_ID), wallet.getWalletName(), wallet.getWalletPin()));
        } catch (IllegalArgumentException exception) {
            log.error("Error occurred while creating user wallets : ", exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, USER_WALLET_CREATION_EXCEPTION.getCode(), HttpStatus.BAD_REQUEST, MediaType.APPLICATION_JSON);
        }  catch (Exception exception) {
            log.error("Error occurred while creating user wallets : ", exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, USER_WALLET_CREATION_EXCEPTION.getCode(), HttpStatus.INTERNAL_SERVER_ERROR,MediaType.APPLICATION_JSON);
        }
    }


    @GetMapping
    public ResponseEntity<List<WalletResponseDto>> getWallets(HttpSession httpSession) {
        try {
            List<WalletResponseDto> response = walletService.getWallets((String) httpSession.getAttribute(SessionKeys.USER_ID));

            return ResponseEntity.status(HttpStatus.OK).body(response);
        } catch (Exception exception) {
            log.error("Error occurred while retrieving user wallets : ", exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, USER_WALLET_RETRIEVAL_EXCEPTION.getCode(), HttpStatus.INTERNAL_SERVER_ERROR,MediaType.APPLICATION_JSON);
        }
    }

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

    @DeleteMapping("/{walletId}")
    public ResponseEntity<Void> deleteWallet(@PathVariable("walletId") String walletId, HttpSession httpSession) {
        try {
            String userId = (String) httpSession.getAttribute("userId");
            if (userId == null) {
                log.error("User ID is missing in session");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }

            // Get the wallet ID from the session for validation
            String sessionWalletId = (String) httpSession.getAttribute("wallet_id");

            // Delete the wallet with session validation
            walletService.deleteWallet(userId, walletId, sessionWalletId);

            // Clear wallet-specific session attributes if they match the deleted wallet
            if (sessionWalletId != null && sessionWalletId.equals(walletId)) {
                httpSession.removeAttribute("wallet_key");
                httpSession.removeAttribute("wallet_id");
                log.info("Cleared wallet session attributes for walletId: {}", walletId);
            }

            return ResponseEntity.ok().build();
        } catch (UnauthorizedWalletAccessException exception) {
            log.error("Unauthorized access to wallet: {}", exception.getMessage());
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        } catch (IllegalArgumentException exception) {
            log.error("Wallet not found or unauthorized access: {}", exception.getMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        } catch (Exception exception) {
            log.error("Error occurred while deleting wallet: ", exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(
                    exception,
                    USER_WALLET_RETRIEVAL_EXCEPTION.getCode(),
                    HttpStatus.INTERNAL_SERVER_ERROR,
                    MediaType.APPLICATION_JSON);
        }
    }

}
