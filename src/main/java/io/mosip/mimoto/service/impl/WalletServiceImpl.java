package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dbentity.PasscodeMetadata;
import io.mosip.mimoto.dbentity.Wallet;
import io.mosip.mimoto.dbentity.WalletMetadata;
import io.mosip.mimoto.dto.WalletResponseDto;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.exception.WalletUnlockEligibilityException;
import io.mosip.mimoto.repository.WalletRepository;
import io.mosip.mimoto.service.WalletService;
import io.mosip.mimoto.util.WalletUtil;
import io.mosip.mimoto.util.WalletValidator;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.function.Supplier;

/**
 * Implementation of {@link WalletService} for managing wallets.
 */
@Slf4j
@Service
public class WalletServiceImpl implements WalletService {

    private final WalletRepository repository;
    private final WalletUtil walletUtil;
    private final WalletValidator validator;

    @Autowired
    public WalletServiceImpl(WalletRepository repository, WalletUtil walletUtil, WalletValidator validator) {
        this.repository = repository;
        this.walletUtil = walletUtil;
        this.validator = validator;
    }

    @Override
    public WalletResponseDto createWallet(String userId, String name, String pin, String confirmPin) throws InvalidRequestException {
        log.info("Creating wallet for user: {}, name: {}", userId, name);

        validator.validateUserId(userId);
        validator.validateWalletName(name);
        validator.validateWalletPin(pin);

        if (!pin.equals(confirmPin)) {
            log.warn("Wallet PIN and confirm PIN are not matching: {}", userId);
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST.getErrorCode(), "Entered PIN and Confirm PIN do not match");
        }

        String walletId = walletUtil.createWallet(userId, name, pin);
        log.debug("Wallet created successfully: {}", walletId);
        return new WalletResponseDto(walletId, name);
    }

    @Override
    public void getWalletUnlockEligibility(String walletId, HttpSession httpSession) throws InvalidRequestException {
        String userId = (String) httpSession.getAttribute(SessionKeys.USER_ID);
        log.info("Unlocking wallet for user: {}, wallet: {}", userId, walletId);

        validator.validateUserId(userId);
        Wallet wallet = repository.findByUserIdAndId(userId, walletId)
                .orElseThrow(getWalletNotFoundExceptionSupplier(userId, walletId));
        validateWalletUnlockEligibility(wallet);
    }


    @Override
    public WalletResponseDto unlockWallet(String walletId, String pin, HttpSession httpSession) throws InvalidRequestException {
        String userId = (String) httpSession.getAttribute(SessionKeys.USER_ID);
        log.info("Unlocking wallet for user: {}, wallet: {}", userId, walletId);

        validator.validateUserId(userId);
        validator.validateWalletPin(pin);

        Wallet wallet = repository.findByUserIdAndId(userId, walletId)
                .orElseThrow(getWalletNotFoundExceptionSupplier(userId, walletId));

        WalletMetadata walletMetadata = wallet.getWalletMetadata();
        PasscodeMetadata passcodeMetadata = walletMetadata.getPasscodeMetadata();

        // Check if the wallet is locked temporarily or permanently
        validateWalletUnlockEligibility(wallet);

        // Allow the user to unlock the wallet only if it is not locked temporarily or permanently
        try {
            String decryptedWalletKey = walletUtil.decryptWalletKey(wallet.getWalletKey(), pin);
            httpSession.setAttribute(SessionKeys.WALLET_KEY, decryptedWalletKey);
            httpSession.setAttribute(SessionKeys.WALLET_ID, walletId);

            //Reset Wallet metadata details
            walletMetadata.setLockUntil(0);
            passcodeMetadata.setRemainingLockCycles(3);
            passcodeMetadata.setRetryRemainingAttempts(5);
            repository.save(wallet);
        } catch (Exception ex) {
            log.error("Failed to unlock the Wallet: {} due to the error: {}", walletId, ex.getMessage(), ex);
            int currentRetryRemainingAttempts = passcodeMetadata.getRetryRemainingAttempts() - 1;
            passcodeMetadata.setRetryRemainingAttempts(currentRetryRemainingAttempts);

            // TODO:  Handle the error scenarios for the database connection
            repository.save(wallet);
            log.info("Stored updated retry remaining attempts details into the database");

            if (currentRetryRemainingAttempts == 0) {
                int currentRemainingLockCycles = passcodeMetadata.getRemainingLockCycles() - 1;
                passcodeMetadata.setRemainingLockCycles(currentRemainingLockCycles);
                long oneHourInMillis = 60 * 60 * 1000;
                walletMetadata.setLockUntil(System.currentTimeMillis() + oneHourInMillis);

                // TODO:  Handle the error scenarios for the database connection
                repository.save(wallet);
                log.info("Stored updated remaining lock cycles details into the database");

                validateWalletUnlockEligibility(wallet);
            } else {
                throw ex;
            }
        }
        return new WalletResponseDto(walletId, wallet.getWalletMetadata().getName());
    }

    private void validateWalletUnlockEligibility(Wallet wallet) throws WalletUnlockEligibilityException {
        WalletMetadata walletMetadata = wallet.getWalletMetadata();
        PasscodeMetadata passcodeMetadata = walletMetadata.getPasscodeMetadata();
        long currentTimeInMilliseconds = System.currentTimeMillis();
        String walletId = wallet.getId();

        // Reset the data if the Wallet temporarily lock time period is expired
        if (passcodeMetadata.getRemainingLockCycles() > 0 && walletMetadata.getLockUntil() != 0 && currentTimeInMilliseconds > walletMetadata.getLockUntil()) {
            walletMetadata.setLockUntil(0);
            passcodeMetadata.setRetryRemainingAttempts(5);
            repository.save(wallet);
        }

        if (passcodeMetadata.getRetryRemainingAttempts() == 0) {
            if (passcodeMetadata.getRemainingLockCycles() > 0) {
                log.warn("Wallet: {} is temporarily locked until: {}, user cannot unlock it", walletId, walletMetadata.getLockUntil());
                throw new WalletUnlockEligibilityException(ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorCode(), ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorMessage());
            } else {
                log.warn("Wallet: {} is permanently locked due to too many failed attempts", walletId);
                throw new WalletUnlockEligibilityException(ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode(), ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorMessage());
            }
        }
    }

    @Override
    public List<WalletResponseDto> getWallets(String userId) {
        log.debug("validating user ID provided");
        validator.validateUserId(userId);

        log.info("Retrieving wallets for user: {}", userId);

        List<Wallet> wallets = repository.findWalletByUserId(userId);
        return wallets.stream()
                .map(wallet -> WalletResponseDto.builder()
                        .walletId(wallet.getId())
                        .walletName(wallet.getWalletMetadata().getName())
                        .build())
                .toList();
    }

    @Override
    public void deleteWallet(String userId, String walletId) throws InvalidRequestException {
        validator.validateUserId(userId);
        Wallet existingWallet = repository.findByUserIdAndId(userId, walletId)
                .orElseThrow(getWalletNotFoundExceptionSupplier(userId, walletId));
        repository.delete(existingWallet);
        log.info("Successfully deleted wallet with ID: {} for user: {}", walletId, userId);
    }

    @NotNull
    private static Supplier<InvalidRequestException> getWalletNotFoundExceptionSupplier(String userId, String walletId) {
        return () -> {
            log.warn("Wallet not found: {} for user: {}", walletId, userId);
            return new InvalidRequestException(ErrorConstants.INVALID_REQUEST.getErrorCode(), "Wallet not found");
        };
    }
}
