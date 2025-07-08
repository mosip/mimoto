package io.mosip.mimoto.service;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.model.PasscodeControl;
import io.mosip.mimoto.model.Wallet;
import io.mosip.mimoto.model.WalletMetadata;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.exception.WalletStatusException;
import io.mosip.mimoto.model.WalletStatus;
import io.mosip.mimoto.repository.WalletRepository;
import io.mosip.mimoto.util.WalletUtil;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import static io.mosip.mimoto.exception.ErrorConstants.WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT;

@Slf4j
@Service
public class WalletUnlockHandler {

    private final WalletRepository repository;
    private final WalletUtil walletUtil;

    @Value("${wallet.lockDuration:3600000}")
    public long lockDuration;

    @Value("${wallet.passcode.maxFailedAttemptsAllowedPerCycle:1}")
    public int maxFailedAttemptsAllowedPerCycle;

    @Value("${wallet.passcode.maxLockCyclesAllowed:1}")
    public int maxLockCyclesAllowed;

    @PostConstruct
    public void validateMaxLockCyclesAllowed() {
        if (maxLockCyclesAllowed <= 0) {
            log.warn("Invalid value for maxLockCyclesAllowed: {}. It should be greater than 0 so setting it to 1.", maxLockCyclesAllowed);
            maxLockCyclesAllowed = 1;
        }
        if (maxFailedAttemptsAllowedPerCycle <= 0) {
            log.warn("Invalid value for maxFailedAttemptsAllowedPerCycle: {}. It should be greater than 0 so setting it to 1.", maxFailedAttemptsAllowedPerCycle);
            maxFailedAttemptsAllowedPerCycle = 1;
        }
    }

    public WalletUnlockHandler(WalletRepository repository, WalletUtil walletUtil) {
        this.repository = repository;
        this.walletUtil = walletUtil;
    }

    public void handleUnlock(Wallet wallet, String pin, HttpSession httpSession) throws InvalidRequestException {
        validateWalletStatus(wallet);
        try {
            String decryptedWalletKey = walletUtil.decryptWalletKey(wallet.getWalletKey(), pin);
            handleSuccessfulUnlock(wallet, decryptedWalletKey, httpSession);
        } catch (InvalidRequestException ex) {
            log.error("Failed to unlock Wallet {} due to: {}", wallet.getId(), ex.getMessage(), ex);
            handleFailedUnlock(wallet, ex);
        }
    }

    private void handleSuccessfulUnlock(Wallet wallet, String decryptedWalletKey, HttpSession httpSession) throws InvalidRequestException {
        httpSession.setAttribute(SessionKeys.WALLET_KEY, decryptedWalletKey);
        httpSession.setAttribute(SessionKeys.WALLET_ID, wallet.getId());

        WalletMetadata walletMetadata = wallet.getWalletMetadata();
        PasscodeControl passcodeControl = walletMetadata.getPasscodeControl();

        passcodeControl.setRetryBlockedUntil(null);
        passcodeControl.setCurrentCycleCount(1);
        passcodeControl.setCurrentAttemptCount(1);
        walletMetadata.setStatus(null);
        repository.save(wallet);
    }

    private void handleFailedUnlock(Wallet wallet, InvalidRequestException ex) throws InvalidRequestException {
        WalletMetadata walletMetadata = wallet.getWalletMetadata();
        PasscodeControl passcodeControl = walletMetadata.getPasscodeControl();
        int currentAttemptCount = passcodeControl.getCurrentAttemptCount() + 1;
        passcodeControl.setCurrentAttemptCount(currentAttemptCount);

        boolean isLastSecondAttemptBeforePermanentLock = currentAttemptCount == maxFailedAttemptsAllowedPerCycle && passcodeControl.getCurrentCycleCount() == maxLockCyclesAllowed;
        if (isLastSecondAttemptBeforePermanentLock) {
            walletMetadata.setStatus(WalletStatus.LAST_ATTEMPT_BEFORE_LOCKOUT);
            repository.save(wallet);
            throw new InvalidRequestException(WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorCode(), WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorMessage());
        }

        handleLockCycle(wallet);
        validateWalletStatus(wallet);
        throw ex;
    }

    private void handleLockCycle(Wallet wallet) {
        WalletMetadata walletMetadata = wallet.getWalletMetadata();
        PasscodeControl passcodeControl = walletMetadata.getPasscodeControl();

        if (passcodeControl.getCurrentAttemptCount() > maxFailedAttemptsAllowedPerCycle) {
            passcodeControl.setCurrentCycleCount(passcodeControl.getCurrentCycleCount() + 1);

            if(passcodeControl.getCurrentCycleCount() > maxLockCyclesAllowed){
                passcodeControl.setRetryBlockedUntil(null);
                walletMetadata.setStatus(WalletStatus.PERMANENTLY_LOCKED);
            } else {
                passcodeControl.setRetryBlockedUntil(System.currentTimeMillis() + lockDuration);
                walletMetadata.setStatus(WalletStatus.TEMPORARILY_LOCKED);
            }
        }

        repository.save(wallet);
    }

    public void validateWalletStatus(Wallet wallet) throws WalletStatusException {
        WalletMetadata walletMetadata = wallet.getWalletMetadata();
        WalletStatus walletCurrentStatus = walletMetadata.getStatus();

        handleTemporaryLockExpiration(wallet);

        if (walletCurrentStatus == WalletStatus.PERMANENTLY_LOCKED) {
            throw new WalletStatusException(ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode(), ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorMessage());
        }

        if (walletCurrentStatus == WalletStatus.TEMPORARILY_LOCKED) {
            throw new WalletStatusException(ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorCode(), ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorMessage() + " for " + (lockDuration / (60 * 60 * 1000)) + " hour(s)");
        }
    }

    public void handleTemporaryLockExpiration(Wallet wallet) {
        long currentTimeInMilliseconds = System.currentTimeMillis();
        WalletMetadata walletMetadata = wallet.getWalletMetadata();
        PasscodeControl passcodeControl = walletMetadata.getPasscodeControl();

        boolean isTemporaryLockExpired = walletMetadata.getStatus() == WalletStatus.TEMPORARILY_LOCKED && passcodeControl.getRetryBlockedUntil() != null && currentTimeInMilliseconds > passcodeControl.getRetryBlockedUntil();
        if (isTemporaryLockExpired) {
            passcodeControl.setRetryBlockedUntil(null);
            passcodeControl.setCurrentAttemptCount(1);
            walletMetadata.setStatus(WalletStatus.LOCK_EXPIRED);
            repository.save(wallet);
        }
    }

    public WalletStatus getWalletStatus(Wallet wallet) {
        handleTemporaryLockExpiration(wallet);
        return wallet.getWalletMetadata().getStatus();
    }
}