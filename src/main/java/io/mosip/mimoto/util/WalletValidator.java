package io.mosip.mimoto.util;

import io.mosip.mimoto.dto.WalletRequestDto;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.InvalidRequestException;
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

    @Value("${mosip.inji.user.wallet.pin.validation.regex:^\\d{4,6}$}")
    private String pinRegex;

    @Value("${mosip.inji.user.wallet.name.validation.regex:^[A-Za-z0-9 _.-]{1,50}$}")
    private String nameRegex;

    /**
     * Validates a wallet creation request.
     *
     * @param userId The user ID.
     * @param name   The wallet name.
     * @param pin    The wallet PIN.
     * @throws InvalidRequestException If the request is invalid.
     */
    public void validateWalletRequest(String userId, String name, String pin) throws InvalidRequestException {
        log.debug("Validating wallet request for user: {}, name: {}", userId, name);

        if (userId == null || userId.trim().isEmpty()) {
            log.warn("Invalid user ID: null or empty");
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST.getErrorCode(), "User ID cannot be null or empty");
        }

        if (name == null || !name.matches(nameRegex)) {
            log.warn("Invalid wallet name: {}", name);
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST.getErrorCode(), "Wallet name must be alphanumeric with allowed special characters");
        }

        if (pin == null || !pin.matches(pinRegex)) {
            log.warn("Invalid PIN: {}", pin);
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST.getErrorCode(), "PIN must be numeric with 4 or 6 digits");
        }
    }
}
