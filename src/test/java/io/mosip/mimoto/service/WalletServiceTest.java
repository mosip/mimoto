package io.mosip.mimoto.service;

import io.mosip.mimoto.dbentity.Wallet;
import io.mosip.mimoto.dto.WalletResponseDto;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.repository.WalletRepository;
import io.mosip.mimoto.service.impl.WalletServiceImpl;
import io.mosip.mimoto.util.WalletUtil;
import io.mosip.mimoto.util.WalletValidator;
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
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class WalletServiceTest {

    @Mock
    private WalletRepository walletRepository;

    @Mock
    private WalletUtil walletHelper;

    @Mock
    private WalletValidator walletValidator;

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
        verify(walletValidator).validateUserId(userId);
        verify(walletValidator).validateWalletName(name);
        verify(walletValidator).validateWalletPin(pin);

        verify(walletHelper).createWallet(userId, name, pin);
    }

    @Test
    public void shouldDecryptWalletKeySuccessfully() throws Exception {
        when(walletRepository.findByUserIdAndId(userId, walletId)).thenReturn(Optional.of(wallet));
        when(walletHelper.decryptWalletKey(encryptedWalletKey, pin)).thenReturn(decryptedWalletKey);

        String result = walletService.getWalletKey(userId, walletId, pin);

        assertEquals(decryptedWalletKey, result);
        verify(walletRepository).findByUserIdAndId(userId, walletId);
        verify(walletHelper).decryptWalletKey(encryptedWalletKey, pin);
    }

    @Test
    public void shouldThrowInvalidRequestExceptionIfWalletNotFoundForGivenUserIdAndWalletId() {
        when(walletRepository.findByUserIdAndId(userId, walletId)).thenReturn(Optional.empty());

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                walletService.getWalletKey(userId, walletId, pin));

        assertEquals("invalid_request", exception.getErrorCode());
        assertEquals("invalid_request --> Wallet not found", exception.getMessage());
        verify(walletRepository).findByUserIdAndId(userId, walletId);
        verifyNoInteractions(walletHelper);
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
        verify(walletRepository).findWalletIdByUserId(userId);
    }

    @Test
    public void shouldReturnEmptyListIfNoWalletsFoundForGivenUserId() {
        when(walletRepository.findWalletIdByUserId(userId)).thenReturn(List.of());

        List<WalletResponseDto> result = walletService.getWallets(userId);

        assertTrue(result.isEmpty());
        verify(walletRepository).findWalletIdByUserId(userId);
    }

    @Test
    public void shouldThrowInvalidRequestExceptionIfAnyErrorOccurredWhileCreatingWallet() throws Exception {
        when(walletHelper.createWallet(userId, name, pin)).thenThrow(new InvalidRequestException("INVALID_REQUEST", "Test Exception"));

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                walletService.createWallet(userId, name, pin));

        assertEquals("INVALID_REQUEST", exception.getErrorCode());
        assertEquals("INVALID_REQUEST --> Test Exception", exception.getMessage());
        verify(walletHelper).createWallet(userId, name, pin);
    }
}