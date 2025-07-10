package io.mosip.mimoto.service;

import io.mosip.mimoto.exception.WalletStatusException;
import io.mosip.mimoto.model.Wallet;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.repository.WalletRepository;
import io.mosip.mimoto.util.WalletUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class WalletUnlockService {
    private final WalletUtil walletUtil;
    private final WalletLockManager walletLockManager;
    private final WalletStatusService walletStatusService;

    private final WalletRepository walletRepository;

    public WalletUnlockService(WalletUtil walletUtil, WalletLockManager walletLockManager, WalletStatusService walletStatusService, WalletRepository walletRepository) {
        this.walletUtil = walletUtil;
        this.walletLockManager = walletLockManager;
        this.walletStatusService = walletStatusService;
        this.walletRepository = walletRepository;
    }

    public String handleUnlock(Wallet wallet, String pin) throws InvalidRequestException {
        wallet = walletLockManager.resetTemporaryLockIfExpired(wallet);
        walletStatusService.validateWalletStatus(wallet);
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
            walletStatusService.validateLastAttemptBeforeLockout(wallet);
            wallet = walletLockManager.resetTemporaryLockIfExpired(wallet);
            walletStatusService.validateWalletStatus(wallet);
            walletRepository.save(wallet);
        } catch (WalletStatusException | InvalidRequestException ex) {
            walletRepository.save(wallet);
            throw ex;
        }
    }
}