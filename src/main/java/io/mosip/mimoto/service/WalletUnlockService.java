package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.WalletLockedException;
import io.mosip.mimoto.model.Wallet;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.model.WalletLockStatus;
import io.mosip.mimoto.repository.WalletRepository;
import io.mosip.mimoto.util.WalletUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class WalletUnlockService {
    private final WalletUtil walletUtil;
    private final WalletLockManager walletLockManager;
    private final WalletLockStatusService walletLockStatusService;

    private final WalletRepository walletRepository;

    public WalletUnlockService(WalletUtil walletUtil, WalletLockManager walletLockManager, WalletLockStatusService walletLockStatusService, WalletRepository walletRepository) {
        this.walletUtil = walletUtil;
        this.walletLockManager = walletLockManager;
        this.walletLockStatusService = walletLockStatusService;
        this.walletRepository = walletRepository;
    }

    public String handleUnlock(Wallet wallet, String pin) throws InvalidRequestException {
        wallet = walletLockManager.resetTemporaryLockIfExpired(wallet);
        throwExceptionIfWalletIsLocked(wallet);
        try {
            String decryptedWalletKey = walletUtil.decryptWalletKey(wallet.getWalletKey(), pin);
            wallet = walletLockManager.resetLockState(wallet);
            walletRepository.save(wallet);
            return decryptedWalletKey;
        } catch (InvalidRequestException ex) {
            log.error("Failed to unlock Wallet {} due to: {}", wallet.getId(), ex.getMessage(), ex);
            handleFailedUnlock(wallet);
            throw ex;
        }
    }

    private void handleFailedUnlock(Wallet wallet) {
        try {
            wallet = walletLockManager.enforceLockCyclePolicy(wallet);
            throwExceptionIfLastAttemptLeftForUnlock(wallet);
            wallet = walletLockManager.resetTemporaryLockIfExpired(wallet);
            throwExceptionIfWalletIsLocked(wallet);
            walletRepository.save(wallet);
        } catch (Exception ex) {
            walletRepository.save(wallet);
            throw ex;
        }
    }

    private void throwExceptionIfWalletIsLocked(Wallet wallet) throws WalletLockedException {
        ErrorDTO errorDTO = walletLockStatusService.getErrorBasedOnWalletLockStatus(wallet);

        if (errorDTO != null) {
            String errorCode = errorDTO.getErrorCode();
            if (errorCode.equals(WalletLockStatus.TEMPORARILY_LOCKED.getValue()) || errorCode.equals(WalletLockStatus.PERMANENTLY_LOCKED.getValue())) {
                throw new WalletLockedException(errorDTO.getErrorCode(), errorDTO.getErrorMessage());
            }
        }
    }

    private void throwExceptionIfLastAttemptLeftForUnlock(Wallet wallet) throws InvalidRequestException {
        ErrorDTO errorDTO = walletLockStatusService.getErrorBasedOnWalletLockStatus(wallet);

        if (errorDTO != null) {
            String errorCode = errorDTO.getErrorCode();
            if (errorCode.equals(WalletLockStatus.LAST_ATTEMPT_BEFORE_LOCKOUT.getValue())) {
                throw new InvalidRequestException(
                        ErrorConstants.WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorCode(),
                        ErrorConstants.WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorMessage());
            }
        }
    }
}