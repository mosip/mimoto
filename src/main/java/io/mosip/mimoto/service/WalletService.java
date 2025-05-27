package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.WalletResponseDto;
import io.mosip.mimoto.exception.InvalidRequestException;
import jakarta.servlet.http.HttpSession;

import java.util.List;

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
     *                                 Example: Wallet PIN and Confirm Wallet PIN received in request don't match
     */
    WalletResponseDto createWallet(String userId, String name, String pin, String confirmPin) throws InvalidRequestException;

    /**
     * Retrieves the decrypted wallet key.
     *
     * @param userId      The user ID.
     * @param walletId    The wallet ID.
     * @param pin         The wallet PIN.
     * @param httpSession
     * @return The decrypted wallet key.
     * @throws InvalidRequestException If the wallet is not found or PIN is invalid.
     */
    String getWalletKey(String userId, String walletId, String pin, HttpSession httpSession) throws InvalidRequestException;

    /**
     * Retrieves all wallets for a user.
     *
     * @param userId The user ID.
     * @return List of wallet responses.
     * @throws InvalidRequestException If the request fails.
     */
    List<WalletResponseDto> getWallets(String userId);

    void deleteWallet(String userId, String walletId) throws InvalidRequestException;
}
