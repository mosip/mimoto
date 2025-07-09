package io.mosip.mimoto.service;

import io.mosip.mimoto.exception.WalletStatusException;
import io.mosip.mimoto.model.PasscodeControl;
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
        PasscodeControl passcodeControl = wallet.getWalletMetadata().getPasscodeControl();

        initPasscodeControlCounters(wallet, passcodeControl);

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

    private void initPasscodeControlCounters(Wallet wallet, PasscodeControl passcodeControl) {
        // Set the current attempt count to 1 if this is the first unlock attempt in the current cycle
        if (passcodeControl.getCurrentAttemptCount() == 0) {
            passcodeControl.setCurrentAttemptCount(1);
        }

        // Set the current cycle count to 1 if this is the first unlock attempt in the entire lock cycle
        if (passcodeControl.getCurrentCycleCount() == 0) {
            passcodeControl.setCurrentCycleCount(1);
        }

        walletRepository.save(wallet);
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