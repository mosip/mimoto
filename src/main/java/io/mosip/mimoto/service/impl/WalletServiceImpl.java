package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.dbentity.Wallet;
import io.mosip.mimoto.dto.WalletResponseDto;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.repository.WalletRepository;
import io.mosip.mimoto.service.WalletService;
import io.mosip.mimoto.util.WalletUtil;
import io.mosip.mimoto.util.WalletValidator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

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
    public String createWallet(String userId, String name, String pin, String confirmPin) throws InvalidRequestException {
        log.info("Creating wallet for user: {}, name: {}", userId, name);

        validator.validateUserId(userId);
        validator.validateWalletName(name);
        validator.validateWalletPin(pin);
        validator.validateWalletPin(confirmPin);

        if (!pin.equals(confirmPin)) {
            log.warn("Wallet PIN and confirm PIN are not matching: {}", userId);
            throw new InvalidRequestException(ErrorConstants.INVALID_REQUEST.getErrorCode(), "Entered PIN and confirmation PIN do not match");
        }

        String walletId = walletUtil.createWallet(userId, name, pin);
        log.debug("Wallet created successfully: {}", walletId);
        return walletId;

    }

    @Override
    public String getWalletKey(String userId, String walletId, String pin) throws InvalidRequestException {
        log.info("Retrieving wallet key for user: {}, wallet: {}", userId, walletId);

        validator.validateUserId(userId);
        validator.validateWalletPin(pin);

        return repository.findByUserIdAndId(userId, walletId)
                .map(wallet -> walletUtil.decryptWalletKey(wallet.getWalletKey(), pin))
                .orElseThrow(() -> {
                    log.warn("Wallet not found: {} for user: {}", walletId, userId);
                    return new InvalidRequestException(ErrorConstants.INVALID_REQUEST.getErrorCode(), "Wallet not found");
                });

    }

    @Override
    public List<WalletResponseDto> getWallets(String userId) {
        log.info("Retrieving wallets for user: {}", userId);

        List<String> walletIds = repository.findWalletIdByUserId(userId);
        return walletIds.stream()
                .map(id -> WalletResponseDto.builder().walletId(id).build())
                .collect(Collectors.toList());

    }

    @Override
    public void deleteWallet(String userId, String walletId) throws InvalidRequestException{
        validator.validateUserId(userId);
        Wallet existingWallet = repository.findByUserIdAndId(userId, walletId)
                .orElseThrow(() -> {
                    log.warn("Wallet not found: {} for user: {}", walletId, userId);
                    return new InvalidRequestException(ErrorConstants.INVALID_REQUEST.getErrorCode(), "Wallet not found");
                });
        repository.delete(existingWallet);
        log.info("Successfully deleted wallet with ID: {} for user: {}", walletId, userId);

    }
}
