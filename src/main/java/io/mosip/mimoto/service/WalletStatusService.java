package io.mosip.mimoto.service;

import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.exception.WalletLockedException;
import io.mosip.mimoto.model.Wallet;
import io.mosip.mimoto.model.WalletMetadata;
import io.mosip.mimoto.model.WalletLockStatus;
import org.springframework.stereotype.Service;

@Service
public class WalletStatusService {



    public WalletLockStatus getWalletStatus(Wallet wallet) {
        return wallet.getWalletMetadata().getLockStatus();
    }

    public void validateWalletStatus(Wallet wallet) throws WalletLockedException {
        WalletMetadata metadata = wallet.getWalletMetadata();
        WalletLockStatus currentStatus = metadata.getLockStatus();

        if (currentStatus == WalletLockStatus.PERMANENTLY_LOCKED) {
            throw new WalletLockedException(ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode(), ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorMessage());
        }

        if (currentStatus == WalletLockStatus.TEMPORARILY_LOCKED) {
            throw new WalletLockedException(
                    ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorCode(),
                    ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorMessage()
            );
        }
    }

    public void validateLastAttemptBeforeLockout(Wallet wallet) throws InvalidRequestException {
        WalletMetadata walletMetadata = wallet.getWalletMetadata();
        if (walletMetadata.getLockStatus() == WalletLockStatus.LAST_ATTEMPT_BEFORE_LOCKOUT) {
            throw new InvalidRequestException(
                    ErrorConstants.WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorCode(),
                    ErrorConstants.WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorMessage()
            );
        }
    }
}