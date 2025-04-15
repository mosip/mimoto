package io.mosip.mimoto.controller;

import io.mosip.kernel.core.crypto.exception.InvalidDataException;
import io.mosip.mimoto.dto.ErrorDTO;
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
            return ResponseEntity.status(HttpStatus.OK).body(walletService.createWallet((String) httpSession.getAttribute("userId"), wallet.getWalletName(), wallet.getWalletPin()));
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
            List<WalletResponseDto> response = walletService.getWallets((String) httpSession.getAttribute("userId"));

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
            String walletKey = walletService.getWalletKey((String) httpSession.getAttribute("userId"), walletId, wallet.getWalletPin());

            if (null != walletKey) {
                httpSession.setAttribute("wallet_key", walletKey);
                httpSession.setAttribute("wallet_id", walletId);
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
