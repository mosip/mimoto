package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.dbentity.Wallet;
import io.mosip.mimoto.dto.WalletResponseDto;
import io.mosip.mimoto.repository.WalletRepository;
import io.mosip.mimoto.service.WalletService;
import io.mosip.mimoto.util.WalletUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;


@Slf4j
@Service
public class WalletServiceImpl implements WalletService {

    @Autowired
    private WalletRepository walletRepository;

    @Autowired
    private WalletUtil walletHelper;
    @Override
    public String createWallet(String userId, String walletName, String pin) throws Exception {
        // Create a new wallet for the user
        return walletHelper.createWallet(userId, walletName, pin);
    }

    @Override
    public String getWalletKey(String userId, String walletId, String pin) {
        Optional<Wallet> existingWallet = walletRepository.findByUserIdAndId(userId, walletId);
        // Decrypt wallet key using the user's PIN
        return existingWallet.map(wallet -> walletHelper.decryptWalletKey(wallet.getWalletKey(), pin)).orElse(null);
    }

    @Override
    public List<WalletResponseDto> getWallets(String userId) {
        List<String> walletIds = walletRepository.findWalletIdByUserId(userId);
        return walletIds.stream()
                .map(walletId -> new WalletResponseDto(walletId))
                .collect(Collectors.toList());
    }

    @Override
    public void deleteWallet(String userId, String walletId, String sessionWalletId) throws Exception {
        // Validate that the wallet ID matches the session wallet ID
        if (sessionWalletId != null && !sessionWalletId.equals(walletId)) {
            log.error("Wallet ID in request ({}) does not match wallet ID in session ({})", walletId, sessionWalletId);
            throw new UnauthorizedWalletAccessException("Unauthorized access to wallet");
        }

        // Check if the wallet exists and belongs to the user
        Optional<Wallet> existingWallet = walletRepository.findByUserIdAndId(userId, walletId);
        if (existingWallet.isEmpty()) {
            log.error("Wallet not found or unauthorized access for walletId: {} and userId: {}", walletId, userId);
            throw new IllegalArgumentException("Wallet not found or unauthorized access");
        }

        try {
            // The wallet entity has CascadeType.ALL for proofSigningKeys, so they will be deleted automatically
            // Delete the wallet - this will cascade delete the proof signing keys
            walletRepository.delete(existingWallet.get());
            log.info("Successfully deleted wallet with ID: {} for user: {}", walletId, userId);
        } catch (Exception e) {
            log.error("Error occurred while deleting wallet with ID: {} for user: {}", walletId, userId, e);
            throw e;
        }
    }
}