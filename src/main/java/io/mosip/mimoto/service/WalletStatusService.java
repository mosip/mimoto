package io.mosip.mimoto.service;

import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.WalletStatusException;
import io.mosip.mimoto.model.Wallet;
import io.mosip.mimoto.model.WalletMetadata;
import io.mosip.mimoto.model.WalletStatus;
import org.springframework.stereotype.Service;

@Service
public class WalletStatusService {

    private final WalletLockManager walletLockManager;

    public WalletStatusService(WalletLockManager walletLockManager) {
        this.walletLockManager = walletLockManager;
    }

    public WalletStatus getWalletStatus(Wallet wallet) {
        walletLockManager.handleTemporaryLockExpiration(wallet);
        return wallet.getWalletMetadata().getStatus();
    }

    public void validateWalletStatus(Wallet wallet) throws WalletStatusException {
        WalletMetadata metadata = wallet.getWalletMetadata();
        WalletStatus currentStatus = metadata.getStatus();

        if (currentStatus == WalletStatus.PERMANENTLY_LOCKED) {
            throw new WalletStatusException(ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode(), ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorMessage());
        }

        if (currentStatus == WalletStatus.TEMPORARILY_LOCKED) {
            walletLockManager.handleTemporaryLockExpiration(wallet);
            WalletStatus updatedStatus = wallet.getWalletMetadata().getStatus();

            if (updatedStatus == WalletStatus.TEMPORARILY_LOCKED) {
                throw new WalletStatusException(
                        ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorCode(),
                        ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorMessage()
                );
            }
        }
    }
}