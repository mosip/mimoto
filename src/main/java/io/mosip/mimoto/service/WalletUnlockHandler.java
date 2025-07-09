package io.mosip.mimoto.service;

import io.mosip.mimoto.model.Wallet;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.util.WalletUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class WalletUnlockHandler {
    private final WalletUtil walletUtil;
    private final WalletLockManager walletLockManager;
    private final WalletStatusService walletStatusService;

    public WalletUnlockHandler(WalletUtil walletUtil, WalletLockManager walletLockManager, WalletStatusService walletStatusService) {
        this.walletUtil = walletUtil;
        this.walletLockManager = walletLockManager;
        this.walletStatusService = walletStatusService;
    }

    public String handleUnlock(Wallet wallet, String pin) throws InvalidRequestException {
        walletStatusService.validateWalletStatus(wallet);
        try {
            String decryptedWalletKey = walletUtil.decryptWalletKey(wallet.getWalletKey(), pin);
            walletLockManager.resetLockState(wallet);
            return decryptedWalletKey;
        } catch (InvalidRequestException ex) {
            log.error("Failed to unlock Wallet {} due to: {}", wallet.getId(), ex.getMessage(), ex);
            handleFailedUnlock(wallet);
            throw ex;
        }
    }

    private void handleFailedUnlock(Wallet wallet) {
        walletLockManager.incrementAttemptCount(wallet);
        walletLockManager.checkAndUpdateLastAttemptBeforePermanentLockout(wallet);
        walletLockManager.handleLockCycle(wallet);
        walletStatusService.validateWalletStatus(wallet);
    }
}