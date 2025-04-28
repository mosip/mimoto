package io.mosip.mimoto.service;

import io.mosip.mimoto.dbentity.Wallet;
import io.mosip.mimoto.dto.WalletResponseDto;
import io.mosip.mimoto.repository.WalletRepository;
import io.mosip.mimoto.service.impl.WalletServiceImpl;
import io.mosip.mimoto.util.WalletUtil;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.Assert.*;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.any;

@RunWith(MockitoJUnitRunner.class)
public class WalletServiceTest {

    @Mock
    private WalletRepository walletRepository;

    @Mock
    private WalletCredentialsRepository walletCredentialsRepository;

    @Mock
    private WalletUtil walletHelper;

    @InjectMocks
    private WalletServiceImpl walletService;

    private String userId;
    private String name;
    private String walletId;
    private String pin;
    private Wallet wallet;
    private String encryptedWalletKey;
    private String decryptedWalletKey;

    @Before
    public void setUp() {
        userId = UUID.randomUUID().toString();
        walletId = UUID.randomUUID().toString();
        pin = "1234";
        name = "default";
        encryptedWalletKey = "encryptedKey";
        decryptedWalletKey = "decryptedKey";

        wallet = new Wallet();
        wallet.setId(walletId);
        wallet.setUserId(userId);
        wallet.setWalletKey(encryptedWalletKey);
    }

    @Test
    public void shouldCreateWalletSuccessfully() throws Exception {
        String newWalletId = UUID.randomUUID().toString();
        when(walletHelper.createWallet(userId, name, pin)).thenReturn(newWalletId);

        String result = walletService.createWallet(userId, name, pin);

        assertEquals(newWalletId, result);
    }

    @Test
    public void shouldDecryptWalletKeySuccessfully() {
        when(walletRepository.findByUserIdAndId(userId, walletId)).thenReturn(Optional.of(wallet));
        when(walletHelper.decryptWalletKey(encryptedWalletKey, pin)).thenReturn(decryptedWalletKey);

        String result = walletService.getWalletKey(userId, walletId, pin);

        assertEquals(decryptedWalletKey, result);
    }

    @Test
    public void shouldReturnNullIfWalletNotFoundForGivenUserIdAndWalletId() {
        when(walletRepository.findByUserIdAndId(userId, walletId)).thenReturn(Optional.empty());

        String result = walletService.getWalletKey(userId, walletId, pin);

        assertNull(result);
    }

    @Test
    public void shouldReturnListOfWalletResponseDtosForGivenUserId() {
        List<String> walletIds = Arrays.asList(UUID.randomUUID().toString(), UUID.randomUUID().toString());
        when(walletRepository.findWalletIdByUserId(userId)).thenReturn(walletIds);

        List<WalletResponseDto> result = walletService.getWallets(userId);

        assertEquals(walletIds.size(), result.size());
        for (int i = 0; i < walletIds.size(); i++) {
            assertEquals(walletIds.get(i), result.get(i).getWalletId());
        }
    }

    @Test
    public void shouldReturnEmptyListIfNoWalletsFoundForGivenUserId() {
        when(walletRepository.findWalletIdByUserId(userId)).thenReturn(List.of());

        List<WalletResponseDto> result = walletService.getWallets(userId);

        assertTrue(result.isEmpty());
    }

    @Test(expected = Exception.class)
    public void shouldThrowExceptionIfAnyErrorOccurredWhileCreatingWallet() throws Exception {
        when(walletHelper.createWallet(userId, name, pin)).thenThrow(new Exception("Test Exception"));

        walletService.createWallet(userId, name, pin);
    }

    @Test
    public void shouldDeleteWalletSuccessfully() throws Exception {
        // Arrange
        when(walletRepository.findByUserIdAndId(userId, walletId)).thenReturn(Optional.of(wallet));
        String sessionWalletId = walletId; // Session wallet ID matches the wallet ID

        // Act
        walletService.deleteWallet(userId, walletId, sessionWalletId);

        // Assert
        verify(walletRepository).delete(wallet);
    }

    @Test
    public void shouldDeleteWalletSuccessfullyWithNullSessionWalletId() throws Exception {
        // Arrange
        when(walletRepository.findByUserIdAndId(userId, walletId)).thenReturn(Optional.of(wallet));
        String sessionWalletId = null; // No session wallet ID (backward compatibility)

        // Act
        walletService.deleteWallet(userId, walletId, sessionWalletId);

        // Assert
        verify(walletRepository).delete(wallet);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowIllegalArgumentExceptionWhenWalletNotFound() throws Exception {
        // Arrange
        when(walletRepository.findByUserIdAndId(userId, walletId)).thenReturn(Optional.empty());
        String sessionWalletId = walletId;

        // Act
        walletService.deleteWallet(userId, walletId, sessionWalletId);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowIllegalArgumentExceptionWhenUserIdDoesNotMatch() throws Exception {
        // Arrange
        String differentUserId = UUID.randomUUID().toString();
        String sessionWalletId = walletId;

        // Act
        walletService.deleteWallet(differentUserId, walletId, sessionWalletId);
    }

    @Test(expected = UnauthorizedWalletAccessException.class)
    public void shouldThrowUnauthorizedWalletAccessExceptionWhenSessionWalletIdDoesNotMatch() throws Exception {
        // Arrange
        String sessionWalletId = UUID.randomUUID().toString(); // Different from walletId

        // Act
        walletService.deleteWallet(userId, walletId, sessionWalletId);
    }

    @Test(expected = Exception.class)
    public void shouldPropagateExceptionWhenErrorOccursDuringDeletion() throws Exception {
        // Arrange
        when(walletRepository.findByUserIdAndId(userId, walletId)).thenReturn(Optional.of(wallet));
        doThrow(new RuntimeException("Database error")).when(walletRepository).delete(any(Wallet.class));
        String sessionWalletId = walletId;

        // Act
        walletService.deleteWallet(userId, walletId, sessionWalletId);
    }
}