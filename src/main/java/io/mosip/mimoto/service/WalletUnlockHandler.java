package io.mosip.mimoto.service;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.model.Wallet;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.util.WalletUtil;
import jakarta.servlet.http.HttpSession;
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

    public void handleUnlock(Wallet wallet, String pin, HttpSession httpSession) throws InvalidRequestException {
        walletStatusService.validateWalletStatus(wallet);
        try {
            String decryptedWalletKey = walletUtil.decryptWalletKey(wallet.getWalletKey(), pin);
            httpSession.setAttribute(SessionKeys.WALLET_KEY, decryptedWalletKey);
            httpSession.setAttribute(SessionKeys.WALLET_ID, wallet.getId());
            walletLockManager.resetLockState(wallet);
        } catch (InvalidRequestException ex) {
            log.error("Failed to unlock Wallet {} due to: {}", wallet.getId(), ex.getMessage(), ex);
            handleFailedUnlock(wallet, ex);
        }
    }

    private void handleFailedUnlock(Wallet wallet, InvalidRequestException ex) throws InvalidRequestException {
        walletLockManager.incrementAttemptCount(wallet);
        walletLockManager.checkAndUpdateLastAttemptBeforePermanentLockout(wallet);
        walletLockManager.handleLockCycle(wallet);
        walletStatusService.validateWalletStatus(wallet);
        throw ex;
    }
}