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
        passcodeControl.setFailedAttemptCount(passcodeControl.getFailedAttemptCount() + 1);

        if (passcodeControl.getCurrentCycleCount() == 0) {
            passcodeControl.setCurrentCycleCount(1);
        }

        boolean isLastSecondAttemptBeforePermanentLock = passcodeControl.getFailedAttemptCount() == walletPasscodeConfig.getMaxFailedAttemptsAllowedPerCycle() - 1 && passcodeControl.getCurrentCycleCount() == walletPasscodeConfig.getMaxLockCyclesAllowed();

        if (passcodeControl.getFailedAttemptCount() == walletPasscodeConfig.getMaxFailedAttemptsAllowedPerCycle()) {
            passcodeControl.setCurrentCycleCount(passcodeControl.getCurrentCycleCount() + 1);

            if (passcodeControl.getCurrentCycleCount() > walletPasscodeConfig.getMaxLockCyclesAllowed()) {
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
            passcodeControl.setFailedAttemptCount(0);
            walletMetadata.setStatus(WalletStatus.LOCK_EXPIRED);
        }
        return wallet;
    }

    public Wallet resetLockState(Wallet wallet) {
        WalletMetadata metadata = wallet.getWalletMetadata();
        PasscodeControl control = metadata.getPasscodeControl();

        control.setFailedAttemptCount(0);
        control.setCurrentCycleCount(0);
        control.setRetryBlockedUntil(null);
        metadata.setStatus(null);

        return wallet;
    }
}