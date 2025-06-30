package io.mosip.mimoto.service;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.model.Wallet;
import io.mosip.mimoto.model.WalletMetadata;
import io.mosip.mimoto.dto.WalletResponseDto;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.exception.UnauthorizedAccessException;
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
import org.springframework.mock.web.MockHttpSession;

import java.time.Instant;
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

    MockHttpSession mockSession;

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

        mockSession = new MockHttpSession();
        mockSession.setAttribute("clientRegistrationId", "google");
        mockSession.setAttribute(SessionKeys.USER_ID, userId);

        wallet = new Wallet();
        wallet.setId(walletId);
        wallet.setUserId(userId);
        wallet.setWalletKey(encryptedWalletKey);
        WalletMetadata walletMetadata = new WalletMetadata();
        walletMetadata.setEncryptionAlgo("AES");
        walletMetadata.setEncryptionType("symmetric");
        walletMetadata.setName("default");
        wallet.setWalletMetadata(walletMetadata);
    }

    @Test
    public void shouldCreateWalletSuccessfully() {
        String newWalletId = UUID.randomUUID().toString();
        when(walletHelper.createWallet(userId, name, walletPin)).thenReturn(newWalletId);

        WalletResponseDto result = walletService.createWallet(userId, name, walletPin, walletConfirmPin);

        assertEquals(newWalletId, result.getWalletId());
        assertEquals("default", result.getWalletName());
        verify(walletValidator).validateUserId(userId);
        verify(walletValidator).validateWalletName(name);
        verify(walletValidator).validateWalletPin(walletPin);
        verify(walletHelper).createWallet(userId, name, walletPin);
    }


    @Test
    public void shouldThrowUnAuthorizedAccessExceptionOnCreatingWalletIfUserIdNotFoundInSession() {
        // In case of userId (or any key) not available in session, the default value will be null.
        doThrow(new UnauthorizedAccessException("unauthorized", "User ID not found in session")).when(walletValidator).validateUserId(null);

        UnauthorizedAccessException exception = assertThrows(UnauthorizedAccessException.class, () ->
                walletService.createWallet(null, name, walletPin, walletConfirmPin));

        assertEquals("unauthorized", exception.getErrorCode());
        assertEquals("unauthorized --> User ID not found in session", exception.getMessage());
    }

    @Test
    public void shouldCreateWalletSuccessfullyIfWalletNameIsNotProvided() {
        String newWalletId = UUID.randomUUID().toString();
        when(walletHelper.createWallet(userId, null, walletPin)).thenReturn(newWalletId);

        WalletResponseDto result = walletService.createWallet(userId, null, walletPin, walletConfirmPin);

        assertEquals(newWalletId, result.getWalletId());
        assertNull(result.getWalletName());
        verify(walletValidator).validateUserId(userId);
        verify(walletValidator).validateWalletName(null);
        verify(walletValidator).validateWalletPin(walletPin);

        verify(walletHelper).createWallet(userId, null, walletPin);
    }

    @Test
    public void shouldUnlockWalletSuccessfully() {
        when(walletRepository.findByUserIdAndId(userId, walletId)).thenReturn(Optional.of(wallet));
        when(walletHelper.decryptWalletKey(encryptedWalletKey, walletPin)).thenReturn(decryptedWalletKey);

        WalletResponseDto result = walletService.unlockWallet(walletId, walletPin, mockSession);

        verify(walletRepository).findByUserIdAndId(userId, walletId);
        verify(walletHelper).decryptWalletKey(encryptedWalletKey, walletPin);
        assertEquals(walletId, result.getWalletId());
        assertEquals("default", result.getWalletName());
        assertEquals(decryptedWalletKey, mockSession.getAttribute(SessionKeys.WALLET_KEY));
        assertEquals(walletId, mockSession.getAttribute(SessionKeys.WALLET_ID));
    }

    @Test
    public void shouldThrowInvalidRequestExceptionIfWalletNotFoundForGivenUserIdAndWalletId() {
        when(walletRepository.findByUserIdAndId(userId, walletId)).thenReturn(Optional.empty());

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                walletService.unlockWallet(walletId, walletPin, mockSession));

        assertEquals("invalid_request", exception.getErrorCode());
        assertEquals("invalid_request --> Wallet not found", exception.getMessage());
        verify(walletRepository).findByUserIdAndId(userId, walletId);
        verifyNoInteractions(walletHelper);
    }

    @Test
    public void shouldThrowInvalidPinErrorCodeExceptionWhenDecryptingWalletKeyWithInvalidPin() {
        String invalidPin = "wrongPin";
        when(walletRepository.findByUserIdAndId(userId, walletId)).thenReturn(Optional.of(wallet));
        when(walletHelper.decryptWalletKey(encryptedWalletKey, invalidPin)).thenThrow(new InvalidRequestException("invalid_pin", "Invalid PIN or wallet key provided"));

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                walletService.unlockWallet(walletId, invalidPin, mockSession));

        verify(walletRepository).findByUserIdAndId(userId, walletId);
        assertEquals("invalid_pin", exception.getErrorCode());
        assertEquals("invalid_pin --> Invalid PIN or wallet key provided", exception.getMessage());
    }

    @Test
    public void shouldReturnListOfWalletResponseDtosForGivenUserId() {
        String walletId1 = UUID.randomUUID().toString();
        String walletId2 = UUID.randomUUID().toString();
        WalletMetadata walletMetadata = new WalletMetadata();
        walletMetadata.setEncryptionAlgo("AES");
        walletMetadata.setEncryptionType("symmetric");
        walletMetadata.setName("Test Wallet");
        List<String> walletIds = Arrays.asList(walletId1, walletId2);
        List<String> walletNames = Arrays.asList(null, "Test Wallet");
        Wallet wallet1 = new Wallet(
                walletId1, "mock-user-id", "mock-encrypted-key", new WalletMetadata(), List.of(), Instant.now(), Instant.now()
        );
        Wallet wallet2 = new Wallet(
                walletId2, "mock-user-id-2", "mock-encrypted-key", walletMetadata, List.of(), Instant.now(), Instant.now()
        );
        when(walletRepository.findWalletByUserId(userId)).thenReturn(List.of(wallet1, wallet2));

        List<WalletResponseDto> result = walletService.getWallets(userId);

        assertEquals(walletIds.size(), result.size());
        for (int i = 0; i < walletIds.size(); i++) {
            assertEquals(walletIds.get(i), result.get(i).getWalletId());
            assertEquals(walletNames.get(i), result.get(i).getWalletName());
        }
        verify(walletRepository).findWalletByUserId(userId);
    }

    @Test
    public void shouldReturnEmptyListIfNoWalletsFoundForGivenUserId() {
        when(walletRepository.findWalletByUserId(userId)).thenReturn(List.of());

        List<WalletResponseDto> result = walletService.getWallets(userId);

        assertTrue(result.isEmpty());
        verify(walletRepository).findWalletByUserId(userId);
    }

    @Test
    public void shouldThrowInvalidRequestExceptionIfAnyErrorOccurredWhileCreatingWallet() {
        when(walletHelper.createWallet(userId, name, walletPin)).thenThrow(new InvalidRequestException("INVALID_REQUEST", "Test Exception"));

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                walletService.createWallet(userId, name, walletPin, walletConfirmPin));

        assertEquals("INVALID_REQUEST", exception.getErrorCode());
        assertEquals("INVALID_REQUEST --> Test Exception", exception.getMessage());
        verify(walletHelper).createWallet(userId, name, walletPin);
    }

    @Test
    public void shouldThrowInvalidRequestExceptionIfReceivedPINAndConfirmPINDoNotMatch() {
        walletConfirmPin = "2345";

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                walletService.createWallet(userId, name, walletPin, walletConfirmPin));

        assertEquals("invalid_request", exception.getErrorCode());
        assertEquals("invalid_request --> Entered PIN and Confirm PIN do not match", exception.getMessage());
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