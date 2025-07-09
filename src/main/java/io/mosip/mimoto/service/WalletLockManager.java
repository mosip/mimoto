package io.mosip.mimoto.service;

import io.mosip.mimoto.config.WalletPasscodeConfig;
import io.mosip.mimoto.model.PasscodeControl;
import io.mosip.mimoto.model.Wallet;
import io.mosip.mimoto.model.WalletMetadata;
import io.mosip.mimoto.model.WalletStatus;
import org.springframework.stereotype.Component;

@Component
public class WalletLockManager {
    private final WalletPasscodeConfig walletPasscodeConfig;
    public WalletLockManager(WalletPasscodeConfig walletPasscodeConfig) {
        this.walletPasscodeConfig = walletPasscodeConfig;
    }

    public Wallet enforceLockCyclePolicy(Wallet wallet) {
        WalletMetadata walletMetadata = wallet.getWalletMetadata();
        PasscodeControl passcodeControl = walletMetadata.getPasscodeControl();

        // Increment the current attempt count
        passcodeControl.setCurrentAttemptCount(passcodeControl.getCurrentAttemptCount() + 1);

        boolean isLastSecondAttemptBeforePermanentLock = passcodeControl.getCurrentAttemptCount() == walletPasscodeConfig.getMaxFailedAttemptsAllowedPerCycle() && passcodeControl.getCurrentCycleCount() == walletPasscodeConfig.getMaxLockCyclesAllowed();

        if (passcodeControl.getCurrentAttemptCount() > walletPasscodeConfig.getMaxFailedAttemptsAllowedPerCycle()) {
            passcodeControl.setCurrentCycleCount(passcodeControl.getCurrentCycleCount() + 1);

            if(passcodeControl.getCurrentCycleCount() > walletPasscodeConfig.getMaxLockCyclesAllowed()){
                passcodeControl.setRetryBlockedUntil(null);
                walletMetadata.setStatus(WalletStatus.PERMANENTLY_LOCKED);
            } else {
                passcodeControl.setRetryBlockedUntil(System.currentTimeMillis() + walletPasscodeConfig.getRetryBlockedUntil());
                walletMetadata.setStatus(WalletStatus.TEMPORARILY_LOCKED);
            }
        } else if (isLastSecondAttemptBeforePermanentLock) {
            walletMetadata.setStatus(WalletStatus.LAST_ATTEMPT_BEFORE_LOCKOUT);
        }

        return wallet;
    }

    public Wallet resetTemporaryLockIfExpired(Wallet wallet) {
        WalletMetadata walletMetadata = wallet.getWalletMetadata();
        PasscodeControl passcodeControl = walletMetadata.getPasscodeControl();

        boolean isTemporaryLockExpired = walletMetadata.getStatus() == WalletStatus.TEMPORARILY_LOCKED && passcodeControl.getRetryBlockedUntil() != null && System.currentTimeMillis() > passcodeControl.getRetryBlockedUntil();

        if (isTemporaryLockExpired) {
            passcodeControl.setRetryBlockedUntil(null);
            passcodeControl.setCurrentAttemptCount(0);
            walletMetadata.setStatus(WalletStatus.LOCK_EXPIRED);
        }
        return wallet;
    }

    public Wallet resetLockState(Wallet wallet) {
        WalletMetadata metadata = wallet.getWalletMetadata();
        PasscodeControl control = metadata.getPasscodeControl();

        control.setCurrentAttemptCount(0);
        control.setCurrentCycleCount(0);
        control.setRetryBlockedUntil(null);
        metadata.setStatus(null);

        return wallet;
    }
}