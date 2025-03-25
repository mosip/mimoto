package io.mosip.mimoto.service;

import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.UUID;

public interface WalletService {
    public String createWallet(String userId, String pin, String walletName) throws NoSuchAlgorithmException, Exception;

    String getWalletKey(String userId, String walletId, String pin);

    List<String> getWallets(String userId);
}
