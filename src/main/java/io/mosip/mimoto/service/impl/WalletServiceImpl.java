package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dbentity.PasscodeMetadata;
import io.mosip.mimoto.dbentity.Wallet;
import io.mosip.mimoto.dbentity.WalletMetadata;
import io.mosip.mimoto.dto.GetWalletResponseDto;
import io.mosip.mimoto.dto.WalletResponseDto;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.exception.WalletStatusException;
import io.mosip.mimoto.model.WalletStatus;
import io.mosip.mimoto.repository.WalletRepository;
import io.mosip.mimoto.service.WalletService;
import io.mosip.mimoto.util.WalletUtil;
import io.mosip.mimoto.util.WalletValidator;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.function.Supplier;

import static io.mosip.mimoto.exception.ErrorConstants.LAST_ATTEMPT_BEFORE_PERMANENT_LOCK;

/**
 * Implementation of {@link WalletService} for managing wallets.
 */
@Slf4j
@Service
public class WalletServiceImpl implements WalletService {

    private final WalletRepository repository;
    private final WalletUtil walletUtil;
    private final WalletValidator validator;

    @Value("${wallet.lockDuration:3600000}")
    public long lockUntil;

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
    public WalletResponseDto unlockWallet(String walletId, String pin, HttpSession httpSession) throws InvalidRequestException {
        String userId = (String) httpSession.getAttribute(SessionKeys.USER_ID);
        log.info("Unlocking Wallet: {} for User: {}", walletId, userId);

        validator.validateUserId(userId);
        validator.validateWalletPin(pin);

        Wallet wallet = repository.findByUserIdAndId(userId, walletId)
                .orElseThrow(getWalletNotFoundExceptionSupplier(userId, walletId));
        WalletMetadata walletMetadata = wallet.getWalletMetadata();
        PasscodeMetadata passcodeMetadata = walletMetadata.getPasscodeMetadata();

        validateWalletStatus(wallet);

        try {
            String decryptedWalletKey = walletUtil.decryptWalletKey(wallet.getWalletKey(), pin);
            httpSession.setAttribute(SessionKeys.WALLET_KEY, decryptedWalletKey);
            httpSession.setAttribute(SessionKeys.WALLET_ID, walletId);

            updateWalletMetadata(wallet, 0L, 1, 0, WalletStatus.ACTIVE);
        } catch (InvalidRequestException ex) {
            log.error("Failed to unlock the Wallet: {} due to the error: {}", walletId, ex.getMessage(), ex);
            int currentFailedAttempts = passcodeMetadata.getFailedAttempts() + 1;

            // Handle Wallet Temporary Lock
            if (currentFailedAttempts == maxFailedAttemptsAllowedPerCycle) {
                wallet.getWalletMetadata().setLockUntil(System.currentTimeMillis() + lockUntil);
                passcodeMetadata.setCurrentLockCycle(passcodeMetadata.getCurrentLockCycle() + 1);
                walletMetadata.setStatus(WalletStatus.TEMPORARILY_LOCKED);
            }

            // Handle Wallet Permanent Lock
            if (passcodeMetadata.getCurrentLockCycle() > maxLockCyclesAllowed) {
                walletMetadata.setStatus(WalletStatus.PERMANENTLY_LOCKED);
            }

            updateWalletMetadata(wallet, walletMetadata.getLockUntil(), passcodeMetadata.getCurrentLockCycle(), currentFailedAttempts, walletMetadata.getStatus());
            validateWalletStatus(wallet);
            throw ex;
        }
        return new WalletResponseDto(walletId, wallet.getWalletMetadata().getName());
    }

    private void validateWalletStatus(Wallet wallet) throws WalletStatusException {
        WalletMetadata walletMetadata = wallet.getWalletMetadata();
        PasscodeMetadata passcodeMetadata = walletMetadata.getPasscodeMetadata();
        long currentTimeInMilliseconds = System.currentTimeMillis();
        String walletId = wallet.getId();

        boolean isTemporaryLockExpired = passcodeMetadata.getCurrentLockCycle() <= maxLockCyclesAllowed && walletMetadata.getLockUntil() != 0 && currentTimeInMilliseconds > walletMetadata.getLockUntil();

        if (isTemporaryLockExpired) {
            updateWalletMetadata(wallet, 0L, passcodeMetadata.getCurrentLockCycle(), 0, WalletStatus.READY_FOR_UNLOCK);
        }

        boolean isLastSecondAttemptBeforePermanentLock = passcodeMetadata.getFailedAttempts() == maxFailedAttemptsAllowedPerCycle - 1 && passcodeMetadata.getCurrentLockCycle() == maxLockCyclesAllowed + 1;

        if (isLastSecondAttemptBeforePermanentLock) {
            throw new WalletStatusException(LAST_ATTEMPT_BEFORE_PERMANENT_LOCK.getErrorCode(), LAST_ATTEMPT_BEFORE_PERMANENT_LOCK.getErrorMessage());
        }

        if (passcodeMetadata.getFailedAttempts() == maxFailedAttemptsAllowedPerCycle) {
            if (passcodeMetadata.getCurrentLockCycle() <= maxLockCyclesAllowed) {
                log.warn("Wallet: {} is temporarily locked until: {}, user cannot unlock it", walletId, walletMetadata.getLockUntil());
                throw new WalletStatusException(ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorCode(), ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorMessage() + " for " + (lockUntil / (60 * 60 * 1000)) + " hour(s)");
            } else {
                log.warn("Wallet: {} is permanently locked due to too many failed attempts", walletId);
                throw new WalletStatusException(ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode(), ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorMessage());
            }
        }
    }

    private void updateWalletMetadata(Wallet wallet, Long lockUntil, Integer currentLockCycle, Integer failedAttempts, WalletStatus walletStatus) {
        WalletMetadata walletMetadata = wallet.getWalletMetadata();
        PasscodeMetadata passcodeMetadata = walletMetadata.getPasscodeMetadata();

        if (lockUntil != null) {
            walletMetadata.setLockUntil(lockUntil);
        }
        if (currentLockCycle != null) {
            passcodeMetadata.setCurrentLockCycle(currentLockCycle);
        }
        if (failedAttempts != null) {
            passcodeMetadata.setFailedAttempts(failedAttempts);
        }
        if (walletStatus != null) {
            walletMetadata.setStatus(walletStatus);
        }

        repository.save(wallet);
    }

    @Override
    public List<GetWalletResponseDto> getWallets(String userId) {
        log.debug("validating user ID provided");
        validator.validateUserId(userId);

        log.info("Retrieving wallets for user: {}", userId);

        List<Wallet> wallets = repository.findWalletByUserId(userId);
        return wallets.stream()
                .map(wallet -> GetWalletResponseDto.builder()
                        .walletId(wallet.getId())
                        .walletName(wallet.getWalletMetadata().getName())
                        .walletStatus(wallet.getWalletMetadata().getStatus())
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
