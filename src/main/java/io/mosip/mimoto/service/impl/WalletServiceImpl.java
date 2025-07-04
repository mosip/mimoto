package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dbentity.Wallet;
import io.mosip.mimoto.dto.GetWalletResponseDto;
import io.mosip.mimoto.dto.WalletResponseDto;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.repository.WalletRepository;
import io.mosip.mimoto.service.WalletService;
import io.mosip.mimoto.service.WalletUnlockHandler;
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
    private final WalletUnlockHandler walletUnlockHandler;

    @Autowired
    public WalletServiceImpl(WalletRepository repository, WalletUtil walletUtil, WalletValidator validator, WalletUnlockHandler walletUnlockHandler) {
        this.repository = repository;
        this.walletUtil = walletUtil;
        this.validator = validator;
        this.walletUnlockHandler = walletUnlockHandler;
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

        walletUnlockHandler.handleUnlock(wallet, pin, httpSession);
        return new WalletResponseDto(walletId, wallet.getWalletMetadata().getName());
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
                        .walletStatus(walletUnlockHandler.getWalletStatus(wallet))
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
