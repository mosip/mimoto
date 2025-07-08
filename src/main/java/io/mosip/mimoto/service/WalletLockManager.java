package io.mosip.mimoto.service;

import io.mosip.mimoto.config.WalletPasscodeConfig;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.model.PasscodeControl;
import io.mosip.mimoto.model.Wallet;
import io.mosip.mimoto.model.WalletMetadata;
import io.mosip.mimoto.model.WalletStatus;
import io.mosip.mimoto.repository.WalletRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import static io.mosip.mimoto.exception.ErrorConstants.WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT;

@Slf4j
@Component
public class WalletLockManager {
    private final WalletPasscodeConfig walletPasscodeConfig;
    private final WalletRepository repository;

    public WalletLockManager(WalletRepository repository, WalletPasscodeConfig walletPasscodeConfig) {
        this.repository = repository;
        this.walletPasscodeConfig = walletPasscodeConfig;
    }

    public void handleLockCycle(Wallet wallet) {
        WalletMetadata walletMetadata = wallet.getWalletMetadata();
        PasscodeControl passcodeControl = walletMetadata.getPasscodeControl();

        if (passcodeControl.getCurrentAttemptCount() > walletPasscodeConfig.getMaxFailedAttemptsAllowedPerCycle()) {
            passcodeControl.setCurrentCycleCount(passcodeControl.getCurrentCycleCount() + 1);

            if(passcodeControl.getCurrentCycleCount() > walletPasscodeConfig.getMaxLockCyclesAllowed()){
                passcodeControl.setRetryBlockedUntil(null);
                walletMetadata.setStatus(WalletStatus.PERMANENTLY_LOCKED);
            } else {
                passcodeControl.setRetryBlockedUntil(System.currentTimeMillis() + walletPasscodeConfig.getRetryBlockedUntil());
                walletMetadata.setStatus(WalletStatus.TEMPORARILY_LOCKED);
            }
        }

        repository.save(wallet);
    }

    public void incrementAttemptCount(Wallet wallet) {
        PasscodeControl control = wallet.getWalletMetadata().getPasscodeControl();
        control.setCurrentAttemptCount(control.getCurrentAttemptCount() + 1);
    }

    public void handleTemporaryLockExpiration(Wallet wallet) {
        WalletMetadata walletMetadata = wallet.getWalletMetadata();
        PasscodeControl passcodeControl = walletMetadata.getPasscodeControl();

        boolean isTemporaryLockExpired = walletMetadata.getStatus() == WalletStatus.TEMPORARILY_LOCKED &&  passcodeControl.getRetryBlockedUntil() != null && System.currentTimeMillis() > passcodeControl.getRetryBlockedUntil();

        if (isTemporaryLockExpired) {
            passcodeControl.setRetryBlockedUntil(null);
            passcodeControl.setCurrentAttemptCount(1);
            walletMetadata.setStatus(WalletStatus.LOCK_EXPIRED);
            repository.save(wallet);
        }
    }

    public void checkAndUpdateLastAttemptBeforePermanentLockout(Wallet wallet) throws InvalidRequestException {
        PasscodeControl passcodeControl = wallet.getWalletMetadata().getPasscodeControl();
         boolean isLastSecondAttemptBeforePermanentLock = passcodeControl.getCurrentAttemptCount() == walletPasscodeConfig.getMaxFailedAttemptsAllowedPerCycle() && passcodeControl.getCurrentCycleCount() == walletPasscodeConfig.getMaxLockCyclesAllowed();

        if (isLastSecondAttemptBeforePermanentLock) {
            wallet.getWalletMetadata().setStatus(WalletStatus.LAST_ATTEMPT_BEFORE_LOCKOUT);
            repository.save(wallet);
            throw new InvalidRequestException(
                    WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorCode(),
                    WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorMessage()
            );
        }
    }

    public void resetLockState(Wallet wallet) {
        WalletMetadata metadata = wallet.getWalletMetadata();
        PasscodeControl control = metadata.getPasscodeControl();

        control.setCurrentAttemptCount(1);
        control.setCurrentCycleCount(1);
        control.setRetryBlockedUntil(null);
        metadata.setStatus(null);

        repository.save(wallet);
    }
}