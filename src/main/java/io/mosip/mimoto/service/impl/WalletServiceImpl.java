package io.mosip.mimoto.service.impl;

import io.mosip.mimoto.dbentity.Wallet;
import io.mosip.mimoto.repository.WalletRepository;
import io.mosip.mimoto.service.WalletService;
import io.mosip.mimoto.util.WalletUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Optional;
import java.util.UUID;


@Slf4j
@Service
public class WalletServiceImpl implements WalletService {

    @Autowired
    private WalletRepository walletRepository;

    @Autowired
    private WalletUtil walletHelper;
    @Override
    public UUID createWallet(UUID userId, String pin) throws Exception {
        // Create a new wallet for the user
        return walletHelper.createEd25519AlgoWallet(userId, pin);
    }

    @Override
    public String getWalletKey(UUID userId, UUID walletId, String pin) {
        Optional<Wallet> existingWallet = walletRepository.findByUserIdAndId(userId, walletId);
        // Decrypt wallet key using the user's PIN
        return existingWallet.map(wallet -> walletHelper.decryptWalletKey(wallet.getWalletKey(), pin)).orElse(null);
    }

    @Override
    public List<UUID> getWallets(UUID userId) {
        return walletRepository.findWalletIdByUserId(userId);
    }
}
