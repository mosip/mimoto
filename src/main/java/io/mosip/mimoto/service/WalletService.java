package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.WalletResponseDto;
import io.mosip.mimoto.exception.InvalidRequestException;

import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.UUID;

/**
 * Service interface for managing wallets.
 */
public interface WalletService {

    /**
     * Creates a new wallet for a user.
     *
     * @param userId The user ID.
     * @param name   The wallet name.
     * @param pin    The wallet PIN.
     * @return The created wallet ID.
     * @throws InvalidRequestException If the request is invalid.
     */
    String createWallet(String userId, String name, String pin) throws InvalidRequestException;

    /**
     * Retrieves the decrypted wallet key.
     *
     * @param userId   The user ID.
     * @param walletId The wallet ID.
     * @param pin      The wallet PIN.
     * @return The decrypted wallet key.
     * @throws InvalidRequestException If the wallet is not found or PIN is invalid.
     */
    String getWalletKey(String userId, String walletId, String pin) throws InvalidRequestException;

    /**
     * Retrieves all wallets for a user.
     *
     * @param userId The user ID.
     * @return List of wallet responses.
     * @throws InvalidRequestException If the request fails.
     */
    List<WalletResponseDto> getWallets(String userId) throws InvalidRequestException;
}
