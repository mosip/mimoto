package io.mosip.mimoto.service;

import io.mosip.mimoto.dbentity.Wallet;
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

@RunWith(MockitoJUnitRunner.class)
public class WalletServiceTest {

    @Mock
    private WalletRepository walletRepository;

    @Mock
    private WalletUtil walletHelper;

    @InjectMocks
    private WalletServiceImpl walletService;

    private UUID userId;
    private UUID walletId;
    private String pin;
    private Wallet wallet;
    private String encryptedWalletKey;
    private String decryptedWalletKey;

    @Before
    public void setUp() {
        userId = UUID.randomUUID();
        walletId = UUID.randomUUID();
        pin = "1234";
        encryptedWalletKey = "encryptedKey";
        decryptedWalletKey = "decryptedKey";

        wallet = new Wallet();
        wallet.setId(walletId);
        wallet.setUserId(userId);
        wallet.setWalletKey(encryptedWalletKey);
    }

    @Test
    public void createWallet_shouldCreateWalletSuccessfully() throws Exception {
        UUID newWalletId = UUID.randomUUID();
        when(walletHelper.createEd25519AlgoWallet(userId, pin)).thenReturn(newWalletId);

        UUID result = walletService.createWallet(userId, pin);

        assertEquals(newWalletId, result);
    }

    @Test
    public void getWalletKey_shouldDecryptWalletKeySuccessfully() {
        when(walletRepository.findByUserIdAndId(userId, walletId)).thenReturn(Optional.of(wallet));
        when(walletHelper.decryptWalletKey(encryptedWalletKey, pin)).thenReturn(decryptedWalletKey);

        String result = walletService.getWalletKey(userId, walletId, pin);

        assertEquals(decryptedWalletKey, result);
    }

    @Test
    public void getWalletKey_shouldReturnNullIfWalletNotFound() {
        when(walletRepository.findByUserIdAndId(userId, walletId)).thenReturn(Optional.empty());

        String result = walletService.getWalletKey(userId, walletId, pin);

        assertNull(result);
    }

    @Test
    public void getWallets_shouldReturnListOfWalletIds() {
        List<UUID> walletIds = Arrays.asList(UUID.randomUUID(), UUID.randomUUID());
        when(walletRepository.findWalletIdByUserId(userId)).thenReturn(walletIds);

        List<UUID> result = walletService.getWallets(userId);

        assertEquals(walletIds, result);
    }

    @Test
    public void getWallets_shouldReturnEmptyListIfNoWalletsFound() {
        when(walletRepository.findWalletIdByUserId(userId)).thenReturn(List.of());

        List<UUID> result = walletService.getWallets(userId);

        assertTrue(result.isEmpty());
    }

    @Test(expected = Exception.class)
    public void createWallet_shouldThrowException() throws Exception {
        when(walletHelper.createEd25519AlgoWallet(userId, pin)).thenThrow(new Exception("Test Exception"));

        walletService.createWallet(userId, pin);
    }
}