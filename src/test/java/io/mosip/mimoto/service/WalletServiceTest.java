package io.mosip.mimoto.service;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.*;
import io.mosip.mimoto.exception.WalletLockedException;
import io.mosip.mimoto.model.Wallet;
import io.mosip.mimoto.model.WalletLockStatus;
import io.mosip.mimoto.model.WalletMetadata;
import io.mosip.mimoto.model.PasscodeControl;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.exception.UnauthorizedAccessException;
import io.mosip.mimoto.repository.WalletRepository;
import io.mosip.mimoto.service.impl.WalletServiceImpl;
import io.mosip.mimoto.util.TestUtilities;
import io.mosip.mimoto.util.WalletUtil;
import io.mosip.mimoto.util.WalletValidator;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.*;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = {WalletServiceImpl.class})
@TestPropertySource(locations = "classpath:application-test.properties")
public class WalletServiceTest {

    @MockBean
    private WalletRepository walletRepository;

    @MockBean
    private WalletUtil walletHelper;

    @MockBean
    private WalletValidator walletValidator;

    @MockBean
    private WalletUnlockService walletUnlockService;

    @MockBean
    private WalletLockStatusService walletStatusService;

    @MockBean
    private WalletLockManager walletLockManager;

    @Autowired
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

        PasscodeControl passcodeControl = TestUtilities.createPasscodeControl(1, 1, null);
        WalletMetadata walletMetadata = TestUtilities.createWalletMetadata("Test Wallet", passcodeControl, null);
        wallet = TestUtilities.createWallet(userId, encryptedWalletKey, walletMetadata);
        walletId = wallet.getId();

    }

    @Value("${wallet.passcode.retryBlockedUntil}")
    private long retryBlockedUntil;

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
        when(walletUnlockService.handleUnlock(wallet, walletPin)).thenReturn(decryptedWalletKey);

        WalletResponseDto responseDto = walletService.unlockWallet(walletId, walletPin, userId);

        verify(walletRepository).findByUserIdAndId(userId, walletId);
        assertEquals(walletId, responseDto.getWalletId());
        assertEquals("Test Wallet", responseDto.getWalletName());
        assertEquals(decryptedWalletKey, responseDto.getDecryptedWalletKey());
    }

    @Test
    public void shouldThrowInvalidRequestExceptionIfWalletNotFoundForGivenUserIdAndWalletId() {
        when(walletRepository.findByUserIdAndId(userId, walletId)).thenReturn(Optional.empty());

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                walletService.unlockWallet(walletId, walletPin, userId));

        assertEquals("invalid_request", exception.getErrorCode());
        assertEquals("invalid_request --> Wallet not found", exception.getMessage());
        verify(walletRepository).findByUserIdAndId(userId, walletId);
        verifyNoInteractions(walletHelper);
    }

    @Test
    public void shouldThrowInvalidPinErrorCodeExceptionWhenDecryptingWalletKeyWithInvalidPin() {
        String invalidPin = "12345678";
        when(walletRepository.findByUserIdAndId(userId, walletId)).thenReturn(Optional.of(wallet));
        doThrow(new InvalidRequestException(ErrorConstants.INVALID_PIN.getErrorCode(), "Invalid PIN or wallet key provided"))
                .when(walletUnlockService).handleUnlock(wallet, invalidPin);

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                walletService.unlockWallet(walletId, invalidPin, userId));

        verify(walletRepository).findByUserIdAndId(userId, walletId);
        assertEquals("invalid_pin", exception.getErrorCode());
        assertEquals("invalid_pin --> Invalid PIN or wallet key provided", exception.getMessage());
    }

    @Test
    public void shouldThrowTemporarilyLockedExceptionWhenUnlockingWalletWhichIsAlreadyLockedTemporarily() {
        PasscodeControl passcodeControl = TestUtilities.createPasscodeControl(6, 2, retryBlockedUntil);
        WalletMetadata walletMetadata = TestUtilities.createWalletMetadata("Test Wallet", passcodeControl, WalletLockStatus.TEMPORARILY_LOCKED);
        wallet = TestUtilities.createWallet(userId, "mock-encrypted-key", walletMetadata);
        walletId = wallet.getId();
        when(walletRepository.findByUserIdAndId(userId, wallet.getId())).thenReturn(Optional.of(wallet));
        String errorMessage = ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorMessage() + " for " + (retryBlockedUntil / (60 * 60 * 1000)) + " hour(s)";
        String expectedErrorMessage = ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorCode() + " --> " + errorMessage;
        doThrow(new WalletLockedException(ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorCode(), errorMessage))
                .when(walletUnlockService).handleUnlock(wallet, walletPin);

        WalletLockedException exception = assertThrows(WalletLockedException.class, () ->
                walletService.unlockWallet(walletId, walletPin, userId));

        verify(walletRepository).findByUserIdAndId(userId, wallet.getId());
        assertEquals(ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorCode(), exception.getErrorCode());
        assertEquals(expectedErrorMessage, exception.getMessage());
    }

    @Test
    public void shouldThrowTemporarilyLockedExceptionWhenUnlockingWalletWithInvalidPinInLastAttemptBeforeTemporaryLock() {
        PasscodeControl passcodeControl = TestUtilities.createPasscodeControl(5, 1, null);
        WalletMetadata walletMetadata = TestUtilities.createWalletMetadata("Test Wallet", passcodeControl, null);
        wallet = TestUtilities.createWallet(userId, encryptedWalletKey, walletMetadata);
        walletPin = "12345678";
        walletId = wallet.getId();

        when(walletRepository.findByUserIdAndId(userId, wallet.getId())).thenReturn(Optional.of(wallet));
        when(walletHelper.decryptWalletKey(encryptedWalletKey, walletPin)).thenThrow(new InvalidRequestException("invalid_pin", "Invalid PIN or wallet key provided"));
        String errorMessage = ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorMessage() + " for " + (retryBlockedUntil / (60 * 60 * 1000)) + " hour(s)";
        String expectedErrorMessage = ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorCode() + " --> " + errorMessage;
        doThrow(new WalletLockedException(ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorCode(), errorMessage))
                .when(walletUnlockService).handleUnlock(wallet, walletPin);

        WalletLockedException exception = assertThrows(WalletLockedException.class, () ->
                walletService.unlockWallet(walletId, walletPin, userId));

        verify(walletRepository).findByUserIdAndId(userId, walletId);
        assertEquals(ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorCode(), exception.getErrorCode());
        assertEquals(expectedErrorMessage, exception.getMessage());
    }

    @Test
    public void shouldThrowPermanentlyLockedExceptionWhenUnlockingWalletWhichIsAlreadyLockedPermanently() {
        PasscodeControl passcodeControl = TestUtilities.createPasscodeControl(6, 4, null);
        WalletMetadata walletMetadata = TestUtilities.createWalletMetadata("Test Wallet", passcodeControl, WalletLockStatus.PERMANENTLY_LOCKED);
        wallet = TestUtilities.createWallet(userId, "mock-encrypted-key", walletMetadata);
        walletId = wallet.getId();
        when(walletRepository.findByUserIdAndId(userId, wallet.getId())).thenReturn(Optional.of(wallet));
        String expectedErrorMessage = ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode() + " --> " + ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorMessage();
        doThrow(new WalletLockedException(ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode(), ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorMessage()))
                .when(walletUnlockService).handleUnlock(wallet, walletPin);

        WalletLockedException exception = assertThrows(WalletLockedException.class, () -> walletService.unlockWallet(walletId, walletPin, userId));

        verify(walletRepository).findByUserIdAndId(userId, wallet.getId());
        assertEquals(ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode(), exception.getErrorCode());
        assertEquals(expectedErrorMessage, exception.getMessage());
    }

    @Test
    public void shouldThrowExceptionWhenUnlockingWalletWithInvalidPinInLastSecondAttemptBeforePermanentLock() {
        PasscodeControl passcodeControl = TestUtilities.createPasscodeControl(4, 3, null);
        WalletMetadata walletMetadata = TestUtilities.createWalletMetadata("Test Wallet", passcodeControl, null);
        wallet = TestUtilities.createWallet(userId, encryptedWalletKey, walletMetadata);
        walletPin = "12345678";
        walletId = wallet.getId();

        when(walletRepository.findByUserIdAndId(userId, wallet.getId())).thenReturn(Optional.of(wallet));
        when(walletHelper.decryptWalletKey(encryptedWalletKey, walletPin)).thenThrow(new InvalidRequestException("invalid_pin", "Invalid PIN or wallet key provided"));
        String expectedErrorMessage = ErrorConstants.WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorCode() + " --> " + ErrorConstants.WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorMessage();
        doThrow(new WalletLockedException(ErrorConstants.WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorCode(), ErrorConstants.WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorMessage()))
                .when(walletUnlockService).handleUnlock(wallet, walletPin);

        WalletLockedException exception = assertThrows(WalletLockedException.class, () ->
                walletService.unlockWallet(walletId, walletPin, userId));

        verify(walletRepository).findByUserIdAndId(userId, walletId);
        assertEquals(ErrorConstants.WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorCode(), exception.getErrorCode());
        assertEquals(expectedErrorMessage, exception.getMessage());
    }

    @Test
    public void shouldThrowPermanentlyLockedExceptionWhenUnlockingWalletWithInvalidPinInLastAttemptBeforePermanentLock() {
        PasscodeControl passcodeControl = TestUtilities.createPasscodeControl(5, 3, null);
        WalletMetadata walletMetadata = TestUtilities.createWalletMetadata("Test Wallet", passcodeControl, WalletLockStatus.LAST_ATTEMPT_BEFORE_LOCKOUT);
        wallet = TestUtilities.createWallet(userId, encryptedWalletKey, walletMetadata);
        walletPin = "12345678";
        walletId = wallet.getId();

        when(walletRepository.findByUserIdAndId(userId, wallet.getId())).thenReturn(Optional.of(wallet));
        when(walletHelper.decryptWalletKey(encryptedWalletKey, walletPin)).thenThrow(new InvalidRequestException("invalid_pin", "Invalid PIN or wallet key provided"));
        String expectedErrorMessage = ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode() + " --> " + ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorMessage();
        doThrow(new WalletLockedException(ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode(), ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorMessage()))
                .when(walletUnlockService).handleUnlock(wallet, walletPin);

        WalletLockedException exception = assertThrows(WalletLockedException.class, () ->
                walletService.unlockWallet(walletId, walletPin, userId));

        verify(walletRepository).findByUserIdAndId(userId, walletId);
        assertEquals(ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode(), exception.getErrorCode());
        assertEquals(expectedErrorMessage, exception.getMessage());
    }


    @Test
    public void shouldReturnListOfWalletResponseDTOsForGivenUserId() {
        PasscodeControl passcodeControl = TestUtilities.createPasscodeControl(5, 3, null);

        WalletMetadata walletMetadata1 = TestUtilities.createWalletMetadata("Test Wallet1", passcodeControl, WalletLockStatus.TEMPORARILY_LOCKED);
        Wallet wallet1 = TestUtilities.createWallet("mock-user-id-1", "mock-encrypted-key", walletMetadata1);

        WalletMetadata walletMetadata2 = TestUtilities.createWalletMetadata("Test Wallet2", passcodeControl, null);
        Wallet wallet2 = TestUtilities.createWallet("mock-user-id-2", "mock-encrypted-key", walletMetadata2);

        List<Wallet> mockWallets = List.of(wallet1, wallet2);

        when(walletLockManager.resetTemporaryLockIfExpired(wallet1)).thenReturn(wallet1);
        when(walletLockManager.resetTemporaryLockIfExpired(wallet2)).thenReturn(wallet2);
        when(walletStatusService.getWalletLockStatus(wallet1)).thenReturn(WalletLockStatus.TEMPORARILY_LOCKED);
        when(walletStatusService.getWalletLockStatus(wallet2)).thenReturn(null);
        when(walletRepository.findWalletByUserId(userId)).thenReturn(mockWallets);

        List<WalletDetailsResponseDto> result = walletService.getWallets(userId);

        verify(walletRepository).findWalletByUserId(userId);
        assertEquals(mockWallets.size(), result.size());
        for (int i = 0; i < mockWallets.size(); i++) {
            Wallet expectedWallet = mockWallets.get(i);

            assertEquals(expectedWallet.getId(), result.get(i).getWalletId());
            assertEquals(expectedWallet.getWalletMetadata().getName(), result.get(i).getWalletName());
            assertEquals(expectedWallet.getWalletMetadata().getLockStatus(), result.get(i).getWalletStatus());
        }
    }

    @Test
    public void shouldReturnEmptyListIfNoWalletsFoundForGivenUserId() {
        when(walletRepository.findWalletByUserId(userId)).thenReturn(List.of());

        List<WalletDetailsResponseDto> result = walletService.getWallets(userId);

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