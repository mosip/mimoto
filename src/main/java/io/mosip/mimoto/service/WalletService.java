package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.WalletResponseDto;

import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.UUID;

public interface WalletService {
    public String createWallet(String userId, String pin, String walletName) throws NoSuchAlgorithmException, Exception;

    String getWalletKey(String userId, String walletId, String pin);

    List<WalletResponseDto> getWallets(String userId);

    void deleteWallet(String userId, String walletId, String sessionWalletId) throws Exception;

    /**
     * @deprecated Use {@link #deleteWallet(String, String, String)} instead
     */
    @Deprecated
    default void deleteWallet(String userId, String walletId) throws Exception {
        deleteWallet(userId, walletId, null);
    }}
