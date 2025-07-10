package io.mosip.mimoto.service;

import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.exception.WalletStatusException;
import io.mosip.mimoto.model.Wallet;
import io.mosip.mimoto.model.WalletMetadata;
import io.mosip.mimoto.model.WalletStatus;
import org.springframework.stereotype.Service;

@Service
public class WalletStatusService {



    public WalletStatus getWalletStatus(Wallet wallet) {
        return wallet.getWalletMetadata().getStatus();
    }

    public void validateWalletStatus(Wallet wallet) throws WalletStatusException {
        WalletMetadata metadata = wallet.getWalletMetadata();
        WalletStatus currentStatus = metadata.getStatus();

        if (currentStatus == WalletStatus.PERMANENTLY_LOCKED) {
            throw new WalletStatusException(ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode(), ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorMessage());
        }

        if (currentStatus == WalletStatus.TEMPORARILY_LOCKED) {
            throw new WalletStatusException(
                    ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorCode(),
                    ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorMessage()
            );
        }
    }

    public void validateLastAttemptBeforeLockout(Wallet wallet) throws InvalidRequestException {
        WalletMetadata walletMetadata = wallet.getWalletMetadata();
        if (walletMetadata.getStatus() == WalletStatus.LAST_ATTEMPT_BEFORE_LOCKOUT) {
            throw new InvalidRequestException(
                    ErrorConstants.WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorCode(),
                    ErrorConstants.WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorMessage()
            );
        }
    }
}