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
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;

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

    private String userId, name, walletId, walletPin, walletConfirmPin, encryptedWalletKey, decryptedWalletKey;
    private Wallet wallet;
    @Before
    public void setUp() {
        userId = UUID.randomUUID().toString();
        walletId = UUID.randomUUID().toString();
        walletPin = "1234";
        walletConfirmPin = "1234";
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
        when(walletHelper.createWallet(userId, name, walletPin)).thenReturn(newWalletId);

        String result = walletService.createWallet(userId, name, walletPin, walletConfirmPin);

        assertEquals(newWalletId, result);
        verify(walletValidator).validateUserId(userId);
        verify(walletValidator).validateWalletName(name);

        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        verify(walletValidator, times(2)).validateWalletPin(captor.capture());
        List<String> capturedPins = captor.getAllValues();

        assertThat(capturedPins, containsInAnyOrder(walletPin, walletConfirmPin));
    }

    @Test
    public void shouldDecryptWalletKeySuccessfully() throws Exception {
        when(walletRepository.findByUserIdAndId(userId, walletId)).thenReturn(Optional.of(wallet));
        when(walletHelper.decryptWalletKey(encryptedWalletKey, walletPin)).thenReturn(decryptedWalletKey);

        String result = walletService.getWalletKey(userId, walletId, walletPin);

        assertEquals(decryptedWalletKey, result);
        verify(walletRepository).findByUserIdAndId(userId, walletId);
        verify(walletHelper).decryptWalletKey(encryptedWalletKey, walletPin);
    }

    @Test
    public void shouldThrowInvalidRequestExceptionIfWalletNotFoundForGivenUserIdAndWalletId() {
        when(walletRepository.findByUserIdAndId(userId, walletId)).thenReturn(Optional.empty());

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                walletService.getWalletKey(userId, walletId, walletPin));

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
        when(walletHelper.createWallet(userId, name, walletPin)).thenThrow(new InvalidRequestException("INVALID_REQUEST", "Test Exception"));

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                walletService.createWallet(userId, name, walletPin, walletConfirmPin));

        assertEquals("INVALID_REQUEST", exception.getErrorCode());
        assertEquals("INVALID_REQUEST --> Test Exception", exception.getMessage());
        verify(walletHelper).createWallet(userId, name, walletPin);
    }

    @Test
    public void shouldThrowInvalidRequestExceptionIfReceivedPINAndConfirmPINDoNotMatch() throws Exception {
        walletConfirmPin = "2345";

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                walletService.createWallet(userId, name, walletPin, walletConfirmPin));

        assertEquals("invalid_request", exception.getErrorCode());
        assertEquals("invalid_request --> Entered PIN and confirmation PIN do not match", exception.getMessage());
    }

    @Test
    public void shouldDeleteWalletSuccessfully() {
        when(walletRepository.findByUserIdAndId(userId, walletId)).thenReturn(Optional.of(wallet));

        walletService.deleteWallet(userId, walletId);

        verify(walletValidator).validateUserId(userId);
        verify(walletRepository).findByUserIdAndId(userId, walletId);
        verify(walletRepository).delete(wallet);
    }

    @Test
    public void shouldThrowInvalidRequestExceptionWhenDeletingNonExistentWallet() {
        when(walletRepository.findByUserIdAndId(userId, walletId)).thenReturn(Optional.empty());

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                walletService.deleteWallet(userId, walletId));

        assertEquals("invalid_request", exception.getErrorCode());
        assertEquals("invalid_request --> Wallet not found", exception.getMessage());
        verify(walletValidator).validateUserId(userId);
        verify(walletRepository).findByUserIdAndId(userId, walletId);
        verify(walletRepository, never()).delete(any(Wallet.class));
    }
}