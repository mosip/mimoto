package io.mosip.mimoto.util;

import io.mosip.mimoto.dto.WalletRequestDto;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class WalletValidator {

    @Value("${mosip.inji.user.wallet.pin.validation.regex}")
    private String pinRegex;

    @Value("${mosip.inji.user.wallet.name.validation.regex}")
    private String walletNameRegex;

    private void validatePin(String pin) {
        if (!pin.matches(pinRegex)) {
            throw new IllegalArgumentException("Pin should be numeric with 4 or 6 digits.");
        }
    }

    private void validateWalletName(String walletName) {
        if (!walletName.matches(walletNameRegex)) {
            throw new IllegalArgumentException("Wallet name should be alphanumeric with spaces and a few allowed special characters.");
        }
    }
    public void validateWalletRequest(WalletRequestDto walletRequest) {
        // Validate both PIN and wallet name
        validatePin(walletRequest.getWalletPin());
        if (!StringUtils.isEmpty(walletRequest.getWalletName())) {
            validateWalletName(walletRequest.getWalletName());
        }
    }
}
