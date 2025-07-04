package io.mosip.mimoto.service;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dbentity.PasscodeMetadata;
import io.mosip.mimoto.dbentity.Wallet;
import io.mosip.mimoto.dbentity.WalletMetadata;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.exception.WalletStatusException;
import io.mosip.mimoto.model.WalletStatus;
import io.mosip.mimoto.repository.WalletRepository;
import io.mosip.mimoto.util.TestUtilities;
import io.mosip.mimoto.util.WalletUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.UUID;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = {WalletUnlockHandler.class})
@TestPropertySource(locations = "classpath:application-test.properties")
class WalletUnlockHandlerTest {

    @MockBean
    private WalletRepository repository;

    @MockBean
    private WalletUtil walletUtil;

    @Autowired
    private WalletUnlockHandler walletUnlockHandler;

    MockHttpSession mockSession;
    private String userId, name, walletId, walletPin, walletConfirmPin, encryptedWalletKey, decryptedWalletKey;
    private Wallet wallet;

    @Value("${wallet.lockDuration}")
    private long lockDuration;

    @BeforeEach
    void setUp() {
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

        PasscodeMetadata passcodeMetadata = TestUtilities.createPasscodeMetadata(1, 1, null);
        WalletMetadata walletMetadata = TestUtilities.createWalletMetadata("Test Wallet", passcodeMetadata, null);
        wallet = TestUtilities.createWallet(userId, encryptedWalletKey, walletMetadata);
        walletId = wallet.getId();
    }


    @Test
    public void shouldUnlockWalletSuccessfully() {
        when(walletUtil.decryptWalletKey(encryptedWalletKey, walletPin)).thenReturn(decryptedWalletKey);

        walletUnlockHandler.handleUnlock(wallet, walletPin, mockSession);

        assertEquals(decryptedWalletKey, mockSession.getAttribute(SessionKeys.WALLET_KEY));
        assertEquals(walletId, mockSession.getAttribute(SessionKeys.WALLET_ID));

        // Verify wallet state reset after successful unlock
        assertEquals(Integer.valueOf(1), wallet.getWalletMetadata().getPasscodeMetadata().getCurrentAttemptCount());
        assertEquals(Integer.valueOf(1), wallet.getWalletMetadata().getPasscodeMetadata().getCurrentCycleCount());
        assertNull(wallet.getWalletMetadata().getPasscodeMetadata().getRetryBlockedUntil());
        assertNull(wallet.getWalletMetadata().getStatus());

        verify(walletUtil, times(1)).decryptWalletKey(encryptedWalletKey, walletPin);
        verify(repository).save(wallet);
    }

    @Test
    public void shouldThrowInvalidPinErrorCodeExceptionWhenDecryptingWalletKeyWithInvalidPin() {
        String invalidPin = "12345678";
        when(walletUtil.decryptWalletKey(encryptedWalletKey, invalidPin)).thenThrow(new InvalidRequestException(ErrorConstants.INVALID_PIN.getErrorCode(), "Invalid PIN"));

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                walletUnlockHandler.handleUnlock(wallet, invalidPin, mockSession));

        assertNull(mockSession.getAttribute(SessionKeys.WALLET_KEY));
        assertNull(mockSession.getAttribute(SessionKeys.WALLET_ID));

        assertEquals(ErrorConstants.INVALID_PIN.getErrorCode(), exception.getErrorCode());
        assertEquals("invalid_pin --> Invalid PIN", exception.getMessage());

        // Verify wallet state updates after first failed attempt in current cycle
        assertEquals(Integer.valueOf(2), wallet.getWalletMetadata().getPasscodeMetadata().getCurrentAttemptCount());
        assertEquals(Integer.valueOf(1), wallet.getWalletMetadata().getPasscodeMetadata().getCurrentCycleCount());
        assertNull(wallet.getWalletMetadata().getPasscodeMetadata().getRetryBlockedUntil());
        assertNull(wallet.getWalletMetadata().getStatus());

        verify(repository).save(wallet);
        verify(walletUtil, times(0)).decryptWalletKey(encryptedWalletKey, walletPin);
    }

    @Test
    public void shouldThrowTemporarilyLockedExceptionWhenUnlockingWalletWhichIsAlreadyLockedTemporarily() {
        PasscodeMetadata passcodeMetadata = TestUtilities.createPasscodeMetadata(6, 2, System.currentTimeMillis() + 3600000);
        WalletMetadata walletMetadata = TestUtilities.createWalletMetadata("Test Wallet", passcodeMetadata, WalletStatus.TEMPORARILY_LOCKED);
        wallet = TestUtilities.createWallet(userId, "mock-encrypted-key", walletMetadata);
        String errorMessage = ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorMessage() + " for " + (lockDuration / (60 * 60 * 1000)) + " hour(s)";
        String expectedErrorMessage = ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorCode() + " --> " + errorMessage;

        WalletStatusException exception = assertThrows(WalletStatusException.class, () ->
                walletUnlockHandler.handleUnlock(wallet, walletPin, mockSession));


        assertNull(mockSession.getAttribute(SessionKeys.WALLET_KEY));
        assertNull(mockSession.getAttribute(SessionKeys.WALLET_ID));
        assertEquals(ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorCode(), exception.getErrorCode());
        assertEquals(expectedErrorMessage, exception.getMessage());

        verifyNoInteractions(repository);
        verify(walletUtil, times(0)).decryptWalletKey(encryptedWalletKey, walletPin);
    }

    @Test
    public void shouldThrowTemporarilyLockedExceptionWhenUnlockingWalletWithInvalidPinInLastAttemptBeforeTemporaryLock() {
        PasscodeMetadata passcodeMetadata = TestUtilities.createPasscodeMetadata(5, 1, null);
        WalletMetadata walletMetadata = TestUtilities.createWalletMetadata("Test Wallet", passcodeMetadata, null);
        wallet = TestUtilities.createWallet(userId, encryptedWalletKey, walletMetadata);
        walletPin = "12345678";
        String errorMessage = ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorMessage() + " for " + (lockDuration / (60 * 60 * 1000)) + " hour(s)";
        String expectedErrorMessage = ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorCode() + " --> " + errorMessage;
        when(walletUtil.decryptWalletKey(encryptedWalletKey, walletPin))
                .thenThrow(new InvalidRequestException(ErrorConstants.INVALID_PIN.getErrorCode(), "Invalid PIN or wallet key provided"));

        // Act & Assert
        WalletStatusException exception = assertThrows(WalletStatusException.class, () ->
                walletUnlockHandler.handleUnlock(wallet, walletPin, mockSession));

        assertNull(mockSession.getAttribute(SessionKeys.WALLET_KEY));
        assertNull(mockSession.getAttribute(SessionKeys.WALLET_ID));
        assertEquals(ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorCode(), exception.getErrorCode());
        assertEquals(expectedErrorMessage, exception.getMessage());

        // Verify wallet state updates after last attempt failed in current cycle
        assertEquals(Integer.valueOf(6), wallet.getWalletMetadata().getPasscodeMetadata().getCurrentAttemptCount());
        assertEquals(Integer.valueOf(2), wallet.getWalletMetadata().getPasscodeMetadata().getCurrentCycleCount());
        assertNotNull(wallet.getWalletMetadata().getPasscodeMetadata().getRetryBlockedUntil()); // Should be blocked
        assertEquals(WalletStatus.TEMPORARILY_LOCKED, wallet.getWalletMetadata().getStatus());

        verify(repository).save(wallet);
        verify(walletUtil, times(1)).decryptWalletKey(encryptedWalletKey, walletPin);
    }

    @Test
    public void shouldThrowPermanentlyLockedExceptionWhenUnlockingWalletWhichIsAlreadyLockedPermanently() {
        PasscodeMetadata passcodeMetadata = TestUtilities.createPasscodeMetadata(6, 4, null);
        WalletMetadata walletMetadata = TestUtilities.createWalletMetadata("Test Wallet", passcodeMetadata, WalletStatus.PERMANENTLY_LOCKED);
        wallet = TestUtilities.createWallet(userId, "mock-encrypted-key", walletMetadata);
        String expectedErrorMessage = ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode() + " --> " + ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorMessage();

        WalletStatusException exception = assertThrows(WalletStatusException.class, () ->
                walletUnlockHandler.handleUnlock(wallet, walletPin, mockSession));

        assertNull(mockSession.getAttribute(SessionKeys.WALLET_KEY));
        assertNull(mockSession.getAttribute(SessionKeys.WALLET_ID));
        assertEquals(ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode(), exception.getErrorCode());
        assertEquals(expectedErrorMessage, exception.getMessage());

        verifyNoInteractions(repository);
        verify(walletUtil, times(0)).decryptWalletKey(encryptedWalletKey, walletPin);
    }

    @Test
    public void shouldThrowExceptionWhenUnlockingWalletWithInvalidPinInLastSecondAttemptBeforePermanentLock() {
        PasscodeMetadata passcodeMetadata = TestUtilities.createPasscodeMetadata(4, 3, null);
        WalletMetadata walletMetadata = TestUtilities.createWalletMetadata("Test Wallet", passcodeMetadata, null);
        wallet = TestUtilities.createWallet(userId, encryptedWalletKey, walletMetadata);
        walletPin = "12345678";
        when(walletUtil.decryptWalletKey(encryptedWalletKey, walletPin))
                .thenThrow(new InvalidRequestException(ErrorConstants.INVALID_PIN.getErrorCode(), "Invalid PIN or wallet key provided"));
        String expectedErrorMessage = ErrorConstants.LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorCode() + " --> " + ErrorConstants.LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorMessage();

        WalletStatusException exception = assertThrows(WalletStatusException.class, () ->
                walletUnlockHandler.handleUnlock(wallet, walletPin, mockSession));

        assertEquals(ErrorConstants.LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorCode(), exception.getErrorCode());
        assertEquals(expectedErrorMessage, exception.getMessage());

        // Verify wallet state updates after last second attempt failed in current cycle
        assertEquals(Integer.valueOf(5), wallet.getWalletMetadata().getPasscodeMetadata().getCurrentAttemptCount()); // Attempt count does not reset yet
        assertEquals(Integer.valueOf(3), wallet.getWalletMetadata().getPasscodeMetadata().getCurrentCycleCount());
        assertNull(wallet.getWalletMetadata().getPasscodeMetadata().getRetryBlockedUntil());
        assertEquals(WalletStatus.LAST_ATTEMPT_BEFORE_LOCKOUT, wallet.getWalletMetadata().getStatus());

        verify(walletUtil, times(1)).decryptWalletKey(encryptedWalletKey, walletPin);
        verify(repository).save(wallet);
    }

    @Test
    public void shouldThrowPermanentlyLockedExceptionWhenUnlockingWalletWithInvalidPinInLastAttemptBeforePermanentLock() {
        PasscodeMetadata passcodeMetadata = TestUtilities.createPasscodeMetadata(5, 3, null);
        WalletMetadata walletMetadata = TestUtilities.createWalletMetadata("Test Wallet", passcodeMetadata, WalletStatus.LAST_ATTEMPT_BEFORE_LOCKOUT);
        wallet = TestUtilities.createWallet(userId, encryptedWalletKey, walletMetadata);
        walletPin = "12345678";
        when(walletUtil.decryptWalletKey(encryptedWalletKey, walletPin))
                .thenThrow(new InvalidRequestException(ErrorConstants.INVALID_PIN.getErrorCode(), "Invalid PIN or wallet key provided"));
        String expectedErrorMessage = ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode() + " --> " + ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorMessage();

        WalletStatusException exception = assertThrows(WalletStatusException.class, () ->
                walletUnlockHandler.handleUnlock(wallet, walletPin, mockSession));

        assertEquals(ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode(), exception.getErrorCode());
        assertEquals(expectedErrorMessage, exception.getMessage());

        // Verify wallet state updates after last second attempt failed in current cycle
        assertEquals(Integer.valueOf(6), wallet.getWalletMetadata().getPasscodeMetadata().getCurrentAttemptCount()); // Attempt count does not reset yet
        assertEquals(Integer.valueOf(4), wallet.getWalletMetadata().getPasscodeMetadata().getCurrentCycleCount());
        assertNull(wallet.getWalletMetadata().getPasscodeMetadata().getRetryBlockedUntil());
        assertEquals(WalletStatus.PERMANENTLY_LOCKED, wallet.getWalletMetadata().getStatus());

        verify(walletUtil, times(1)).decryptWalletKey(encryptedWalletKey, walletPin);
        verify(repository).save(wallet);
    }
}