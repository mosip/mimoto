package io.mosip.mimoto.service;

import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.UUID;

public interface WalletService {
    public UUID createWallet(UUID userId, String pin) throws NoSuchAlgorithmException, Exception;

    String getWalletKey(UUID userId, UUID walletId, String pin);

    List<UUID> getWallets(UUID userId);
}
