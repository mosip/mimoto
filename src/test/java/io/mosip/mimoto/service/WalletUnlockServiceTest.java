package io.mosip.mimoto.service;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.model.PasscodeControl;
import io.mosip.mimoto.model.Wallet;
import io.mosip.mimoto.model.WalletMetadata;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.exception.WalletLockedException;
import io.mosip.mimoto.repository.WalletRepository;
import io.mosip.mimoto.util.TestUtilities;
import io.mosip.mimoto.util.WalletUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = {WalletUnlockService.class})
@TestPropertySource(locations = "classpath:application-test.properties")
class WalletUnlockServiceTest {

    @MockBean
    private WalletUtil walletUtil;

    @MockBean
    private WalletLockManager walletLockManager;

    @MockBean
    private WalletStatusService walletStatusService;

    @MockBean
    private WalletRepository walletRepository;

    @Autowired
    private WalletUnlockService walletUnlockService;

    MockHttpSession mockSession;
    private String walletPin, encryptedWalletKey, decryptedWalletKey;
    private Wallet wallet;

    @BeforeEach
    void setUp() {
        String userId = UUID.randomUUID().toString();
        walletPin = "1234";
        encryptedWalletKey = "encryptedKey";
        decryptedWalletKey = "decryptedKey";

        mockSession = new MockHttpSession();
        mockSession.setAttribute("clientRegistrationId", "google");
        mockSession.setAttribute(SessionKeys.USER_ID, userId);

        PasscodeControl passcodeControl = TestUtilities.createPasscodeControl(1, 1, null);
        WalletMetadata walletMetadata = TestUtilities.createWalletMetadata("Test Wallet", passcodeControl, null);
        wallet = TestUtilities.createWallet(userId, encryptedWalletKey, walletMetadata);
    }

    @Test
    void shouldUnlockWalletSuccessfullyAndReturnDecryptedWalletKeyWhenValidPinIsProvided() throws InvalidRequestException {
        when(walletLockManager.resetTemporaryLockIfExpired(wallet)).thenReturn(wallet);
        doNothing().when(walletStatusService).validateWalletStatus(wallet);
        when(walletUtil.decryptWalletKey(encryptedWalletKey, walletPin)).thenReturn(decryptedWalletKey);

        String result = walletUnlockService.handleUnlock(wallet, walletPin);

        assertEquals(decryptedWalletKey, result);
        verify(walletStatusService, times(1)).validateWalletStatus(wallet);
        verify(walletUtil).decryptWalletKey(encryptedWalletKey, walletPin);
        verify(walletLockManager).resetTemporaryLockIfExpired(wallet);
        verify(walletLockManager).resetLockState(wallet);
        verifyNoMoreInteractions(walletLockManager);
    }

    @Test
    void shouldThrowExceptionAndHandleUnlockFailureWhenInvalidPinIsProvided() throws InvalidRequestException {
        String invalidPin = "12345678";
        when(walletLockManager.resetTemporaryLockIfExpired(wallet)).thenReturn(wallet).thenReturn(wallet);
        when(walletLockManager.enforceLockCyclePolicy(wallet)).thenReturn(wallet);
        doNothing().when(walletStatusService).validateWalletStatus(wallet);
        doNothing().when(walletStatusService).validateLastAttemptBeforeLockout(wallet);
        when(walletUtil.decryptWalletKey(encryptedWalletKey, invalidPin))
                .thenThrow(new InvalidRequestException(ErrorConstants.INVALID_PIN.getErrorCode(), "Invalid PIN"));

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                walletUnlockService.handleUnlock(wallet, invalidPin));

        assertEquals(ErrorConstants.INVALID_PIN.getErrorCode(), exception.getErrorCode());
        assertEquals("invalid_pin --> Invalid PIN", exception.getMessage());

        verify(walletUtil).decryptWalletKey(encryptedWalletKey, invalidPin);
        verify(walletLockManager).enforceLockCyclePolicy(wallet);
        verify(walletStatusService).validateLastAttemptBeforeLockout(wallet);
        verify(walletLockManager,times(2)).resetTemporaryLockIfExpired(wallet);
        verify(walletStatusService, times(2)).validateWalletStatus(wallet);
        verify(walletLockManager, never()).resetLockState(wallet);
        verify(walletRepository, times(1)).save(wallet);
    }

    @Test
    void shouldThrowExceptionWhenWalletIsLockedPermanentlyAfterValidatingInvalidPin() throws InvalidRequestException {
        String invalidPin = "12345678";
        when(walletLockManager.resetTemporaryLockIfExpired(wallet)).thenReturn(wallet).thenReturn(wallet);
        when(walletUtil.decryptWalletKey(encryptedWalletKey, invalidPin))
                .thenThrow(new InvalidRequestException(ErrorConstants.INVALID_PIN.getErrorCode(), "Invalid PIN"));
        when(walletLockManager.enforceLockCyclePolicy(wallet)).thenReturn(wallet);
        doNothing().when(walletStatusService).validateLastAttemptBeforeLockout(wallet);
        doNothing().doThrow(new WalletLockedException(ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode(), ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorMessage())).when(walletStatusService).validateWalletStatus(wallet);
        String expectedErrorMessage = ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode() + " --> " + ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorMessage();

        WalletLockedException exception = assertThrows(WalletLockedException.class, () ->
                walletUnlockService.handleUnlock(wallet, invalidPin));

        assertEquals(ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode(), exception.getErrorCode());
        assertEquals(expectedErrorMessage, exception.getMessage());

        verify(walletUtil).decryptWalletKey(encryptedWalletKey, invalidPin);
        verify(walletLockManager).enforceLockCyclePolicy(wallet);
        verify(walletStatusService).validateLastAttemptBeforeLockout(wallet);
        verify(walletLockManager,times(2)).resetTemporaryLockIfExpired(wallet);
        verify(walletStatusService, times(2)).validateWalletStatus(wallet);
        verify(walletLockManager, never()).resetLockState(wallet);
        verify(walletRepository, times(1)).save(wallet);
    }

    @Test
    void shouldThrowExceptionWhenOnlyOneAttemptIsLeftBeforePermanentLockoutAfterValidatingInvalidPin() throws InvalidRequestException {
        String invalidPin = "12345678";
        when(walletLockManager.resetTemporaryLockIfExpired(wallet)).thenReturn(wallet).thenReturn(wallet);
        when(walletUtil.decryptWalletKey(encryptedWalletKey, invalidPin))
                .thenThrow(new InvalidRequestException(ErrorConstants.INVALID_PIN.getErrorCode(), "Invalid PIN"));
        doNothing().when(walletStatusService).validateWalletStatus(wallet);
        when(walletLockManager.enforceLockCyclePolicy(wallet)).thenReturn(wallet);
        doNothing().when(walletStatusService).validateLastAttemptBeforeLockout(wallet);
        doThrow(new InvalidRequestException(ErrorConstants.WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorCode(), ErrorConstants.WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorMessage())).when(walletStatusService).validateLastAttemptBeforeLockout(wallet);
        String expectedErrorMessage = ErrorConstants.WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorCode() + " --> " + ErrorConstants.WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorMessage();

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                walletUnlockService.handleUnlock(wallet, invalidPin));

        assertEquals(ErrorConstants.WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorCode(), exception.getErrorCode());
        assertEquals(expectedErrorMessage, exception.getMessage());

        verify(walletUtil).decryptWalletKey(encryptedWalletKey, invalidPin);
        verify(walletLockManager).enforceLockCyclePolicy(wallet);
        verify(walletStatusService).validateLastAttemptBeforeLockout(wallet);
        verify(walletLockManager,times(1)).resetTemporaryLockIfExpired(wallet);
        verify(walletStatusService, times(1)).validateWalletStatus(wallet);
        verify(walletLockManager, never()).resetLockState(wallet);
        verify(walletRepository, times(1)).save(wallet);
    }

    @Test
    void shouldThrowExceptionImmediatelyWhenUnlockingWalletIsAlreadyLockedPermanently() throws InvalidRequestException {
        when(walletLockManager.resetTemporaryLockIfExpired(wallet)).thenReturn(wallet);
        WalletLockedException walletLockedException = new WalletLockedException(ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode(), ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorMessage());
        doThrow(walletLockedException).when(walletStatusService).validateWalletStatus(wallet);

        String expectedErrorMessage = ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode() + " --> " + ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorMessage();

        WalletLockedException exception = assertThrows(WalletLockedException.class, () ->
                walletUnlockService.handleUnlock(wallet, walletPin));

        assertEquals(ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode(), exception.getErrorCode());
        assertEquals(expectedErrorMessage, exception.getMessage());

        verify(walletLockManager,times(1)).resetTemporaryLockIfExpired(wallet);
        verify(walletStatusService, times(1)).validateWalletStatus(wallet);
        verifyNoInteractions(walletRepository);
        verifyNoMoreInteractions(walletLockManager);
        verifyNoMoreInteractions(walletStatusService);
    }
}