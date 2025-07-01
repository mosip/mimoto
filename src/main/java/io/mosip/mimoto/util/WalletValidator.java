package io.mosip.mimoto.util;

import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.exception.UnauthorizedAccessException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Utility class for validating wallet-related requests.
 */
@Slf4j
@Component
public class WalletValidator {

    @Value("${mosip.inji.user.wallet.pin.validation.regex:^\\d{6}$}")
    private String pinRegex;

    @Value("${mosip.inji.user.wallet.name.validation.regex:^[A-Za-z0-9 _.-]{0,50}$}")
    private String nameRegex;

    /**
     * Validates the user ID.
     *
     * @param userId The user ID.
     * @throws InvalidRequestException If the User ID is invalid.
     */
    public void validateUserId(String userId) throws InvalidRequestException {
        log.debug("Validating User: {}", userId);
        if(userId == null){
            log.warn("User ID is not available in the session");
            throw new UnauthorizedAccessException(ErrorConstants.UNAUTHORIZED_ACCESS.getErrorCode(), "User ID not found in session");
        }
        if (StringUtils.isBlank(userId)) {
            log.warn("Invalid user ID: null or empty");
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST.getErrorCode(), "User ID cannot be null or empty");
        }
    }

    /**
     * Validates the Wallet name.
     *
     * @param name The Wallet name.
     * @throws InvalidRequestException If the Wallet name is invalid.
     */
    public void validateWalletName(String name) throws InvalidRequestException {
        log.debug("Validating Wallet name: {}", name);
        if (name != null && !name.matches(nameRegex)) {
            log.warn("Invalid Wallet name: {}", name);
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST.getErrorCode(), "Wallet name must be alphanumeric with allowed special characters");
        }
    }

    /**
     * Validates the Wallet PIN.
     *
     * @param pin The Wallet PIN.
     * @throws InvalidRequestException If the Wallet PIN is invalid.
     */
    public void validateWalletPin(String pin) throws InvalidRequestException {
        log.debug("Validating Wallet PIN: {}", pin);
        if (pin == null || !pin.matches(pinRegex)) {
            log.warn("Invalid PIN: {}", pin);
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST.getErrorCode(), "PIN must be numeric with 6 digits");
        }
    }
}
