package io.mosip.mimoto.service;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.model.PasscodeControl;
import io.mosip.mimoto.model.Wallet;
import io.mosip.mimoto.model.WalletMetadata;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.exception.WalletStatusException;
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
@SpringBootTest(classes = {WalletUnlockHandler.class})
@TestPropertySource(locations = "classpath:application-test.properties")
class WalletUnlockHandlerTest {

    @MockBean
    private WalletUtil walletUtil;

    @MockBean
    private WalletLockManager walletLockManager;

    @MockBean
    private WalletStatusService walletStatusService;

    @Autowired
    private WalletUnlockHandler walletUnlockHandler;

    MockHttpSession mockSession;
    private String userId, walletPin, encryptedWalletKey, decryptedWalletKey;
    private Wallet wallet;

    @BeforeEach
    void setUp() {
        userId = UUID.randomUUID().toString();
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
    void shouldUnlockWalletSuccessfullyAndReturnDecryptedWalletKeyWhenValidPinProvided() throws InvalidRequestException {
        when(walletUtil.decryptWalletKey(encryptedWalletKey, walletPin)).thenReturn(decryptedWalletKey);

        String result = walletUnlockHandler.handleUnlock(wallet, walletPin);

        assertEquals(decryptedWalletKey, result);
        verify(walletStatusService, times(1)).validateWalletStatus(wallet);
        verify(walletUtil).decryptWalletKey(encryptedWalletKey, walletPin);
        verify(walletLockManager).resetLockState(wallet);
        verifyNoMoreInteractions(walletLockManager);
    }

    @Test
    void shouldThrowExceptionAndHandleUnlockFailureWhenInvalidPinProvided() throws InvalidRequestException {
        String invalidPin = "12345678";
        when(walletUtil.decryptWalletKey(encryptedWalletKey, invalidPin))
                .thenThrow(new InvalidRequestException(ErrorConstants.INVALID_PIN.getErrorCode(), "Invalid PIN"));

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                walletUnlockHandler.handleUnlock(wallet, invalidPin));

        assertEquals(ErrorConstants.INVALID_PIN.getErrorCode(), exception.getErrorCode());
        assertEquals("invalid_pin --> Invalid PIN", exception.getMessage());

        verify(walletUtil).decryptWalletKey(encryptedWalletKey, invalidPin);
        verify(walletLockManager).incrementAttemptCount(wallet);
        verify(walletLockManager).checkAndUpdateLastAttemptBeforePermanentLockout(wallet);
        verify(walletLockManager).handleLockCycle(wallet);
        verify(walletStatusService, times(2)).validateWalletStatus(wallet);
        verify(walletLockManager, never()).resetLockState(wallet);
    }

    @Test
    void shouldThrowExceptionImmediatelyWhenUnlockingWalletIsLockedTemporarilyOrPermanently() throws InvalidRequestException {
        WalletStatusException walletStatusException = new WalletStatusException(ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode(), ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorMessage());
        doThrow(walletStatusException).when(walletStatusService).validateWalletStatus(wallet);

        String expectedErrorMessage = ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode() + " --> " + ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorMessage();

        WalletStatusException exception = assertThrows(WalletStatusException.class, () ->
                walletUnlockHandler.handleUnlock(wallet, walletPin));

        assertEquals(ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode(), exception.getErrorCode());
        assertEquals(expectedErrorMessage, exception.getMessage());

        verify(walletStatusService, times(1)).validateWalletStatus(wallet);
        verifyNoMoreInteractions(walletStatusService);
        verify(walletLockManager, never()).resetLockState(wallet);
    }
}