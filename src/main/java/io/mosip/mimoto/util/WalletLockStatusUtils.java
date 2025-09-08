package io.mosip.mimoto.util;

import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.model.Wallet;
import io.mosip.mimoto.model.WalletMetadata;
import io.mosip.mimoto.model.WalletLockStatus;

public final class WalletLockStatusUtils {

    private WalletLockStatusUtils() {
        // Prevent instantiation
    }

    public static WalletLockStatus getWalletLockStatus(Wallet wallet) {
        return wallet.getWalletMetadata().getLockStatus();
    }

    public static ErrorDTO getErrorBasedOnWalletLockStatus(Wallet wallet) {
        WalletMetadata metadata = wallet.getWalletMetadata();
        WalletLockStatus currentStatus = metadata.getLockStatus();
        ErrorDTO errorDTO = null;
        if (currentStatus == WalletLockStatus.PERMANENTLY_LOCKED) {
            errorDTO = new ErrorDTO(ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode(),
                    ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorMessage());
        } else if (currentStatus == WalletLockStatus.TEMPORARILY_LOCKED) {
            errorDTO = new ErrorDTO(ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorCode(),
                    ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorMessage());
        } else if (currentStatus == WalletLockStatus.LAST_ATTEMPT_BEFORE_LOCKOUT) {
            errorDTO = new ErrorDTO(ErrorConstants.WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorCode(),
                    ErrorConstants.WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorMessage());
        }
        return errorDTO;
    }
}
