package io.mosip.mimoto.service;

import io.mosip.mimoto.constant.SessionKeys;
import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.model.PasscodeControl;
import io.mosip.mimoto.model.Wallet;
import io.mosip.mimoto.model.WalletMetadata;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.exception.WalletLockedException;
import io.mosip.mimoto.repository.WalletRepository;
import io.mosip.mimoto.util.TestUtilities;
import io.mosip.mimoto.util.WalletLockStatusUtils;
import io.mosip.mimoto.util.WalletUtil;
import org.junit.jupiter.api.*;
import org.junit.runner.RunWith;
import org.mockito.MockedStatic;
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
    private WalletLockService walletLockService;

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
        when(walletLockService.resetTemporaryLockIfExpired(wallet)).thenReturn(wallet);
        when(walletUtil.decryptWalletKey(encryptedWalletKey, walletPin)).thenReturn(decryptedWalletKey);

        try (MockedStatic<WalletLockStatusUtils> mockedStatic = mockStatic(WalletLockStatusUtils.class)) {
            mockedStatic.when(() -> WalletLockStatusUtils.getErrorBasedOnWalletLockStatus(wallet)).thenReturn(null);

            String result = walletUnlockService.handleUnlock(wallet, walletPin);

            assertEquals(decryptedWalletKey, result);
            mockedStatic.verify(() -> WalletLockStatusUtils.getErrorBasedOnWalletLockStatus(wallet), times(1));
            verify(walletUtil).decryptWalletKey(encryptedWalletKey, walletPin);
            verify(walletLockService).resetTemporaryLockIfExpired(wallet);
            verify(walletLockService).resetLockState(wallet);
        }
    }

    @Test
    void shouldThrowExceptionAndHandleUnlockFailureWhenInvalidPinIsProvided() throws InvalidRequestException {
        String invalidPin = "12345678";
        when(walletLockService.resetTemporaryLockIfExpired(wallet)).thenReturn(wallet).thenReturn(wallet);
        when(walletLockService.enforceLockCyclePolicy(wallet)).thenReturn(wallet);
        when(walletUtil.decryptWalletKey(encryptedWalletKey, invalidPin))
                .thenThrow(new InvalidRequestException(ErrorConstants.INVALID_PIN.getErrorCode(), "Invalid PIN"));

        try (MockedStatic<WalletLockStatusUtils> mockedStatic = mockStatic(WalletLockStatusUtils.class)) {
            mockedStatic.when(() -> WalletLockStatusUtils.getErrorBasedOnWalletLockStatus(wallet)).thenReturn(null);

            InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                    walletUnlockService.handleUnlock(wallet, invalidPin));

            assertEquals(ErrorConstants.INVALID_PIN.getErrorCode(), exception.getErrorCode());
            assertEquals("invalid_pin --> Invalid PIN", exception.getMessage());

            verify(walletUtil).decryptWalletKey(encryptedWalletKey, invalidPin);
            verify(walletLockService).enforceLockCyclePolicy(wallet);
            mockedStatic.verify(() -> WalletLockStatusUtils.getErrorBasedOnWalletLockStatus(wallet), times(3));
            verify(walletLockService, times(2)).resetTemporaryLockIfExpired(wallet);
            verify(walletLockService, never()).resetLockState(wallet);
            verify(walletRepository, times(1)).save(wallet);
        }
    }

    @Test
    void shouldThrowExceptionWhenWalletIsLockedPermanentlyAfterValidatingInvalidPin() throws InvalidRequestException {
        String invalidPin = "12345678";
        when(walletLockService.resetTemporaryLockIfExpired(wallet)).thenReturn(wallet).thenReturn(wallet);
        when(walletUtil.decryptWalletKey(encryptedWalletKey, invalidPin))
                .thenThrow(new InvalidRequestException(ErrorConstants.INVALID_PIN.getErrorCode(), "Invalid PIN"));
        when(walletLockService.enforceLockCyclePolicy(wallet)).thenReturn(wallet);

        try (MockedStatic<WalletLockStatusUtils> mockedStatic = mockStatic(WalletLockStatusUtils.class)) {
            mockedStatic.when(() -> WalletLockStatusUtils.getErrorBasedOnWalletLockStatus(wallet))
                    .thenReturn(null)
                    .thenReturn(null)
                    .thenReturn(new ErrorDTO(ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode(), ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorMessage()));
            String expectedErrorMessage = ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode() + " --> " + ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorMessage();

            WalletLockedException exception = assertThrows(WalletLockedException.class, () ->
                    walletUnlockService.handleUnlock(wallet, invalidPin));

            assertEquals(ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode(), exception.getErrorCode());
            assertEquals(expectedErrorMessage, exception.getMessage());

            verify(walletUtil).decryptWalletKey(encryptedWalletKey, invalidPin);
            verify(walletLockService).enforceLockCyclePolicy(wallet);
            verify(walletLockService, times(2)).resetTemporaryLockIfExpired(wallet);
            mockedStatic.verify(() -> WalletLockStatusUtils.getErrorBasedOnWalletLockStatus(wallet), times(3));
            verify(walletLockService, never()).resetLockState(wallet);
            verify(walletRepository, times(1)).save(wallet);
        }
    }

    @Test
    void shouldThrowExceptionWhenOnlyOneAttemptIsLeftBeforePermanentLockoutAfterValidatingInvalidPin() throws InvalidRequestException {
        String invalidPin = "12345678";
        when(walletLockService.resetTemporaryLockIfExpired(wallet)).thenReturn(wallet).thenReturn(wallet);
        when(walletUtil.decryptWalletKey(encryptedWalletKey, invalidPin))
                .thenThrow(new InvalidRequestException(ErrorConstants.INVALID_PIN.getErrorCode(), "Invalid PIN"));
        when(walletLockService.enforceLockCyclePolicy(wallet)).thenReturn(wallet);

        try (MockedStatic<WalletLockStatusUtils> mockedStatic = mockStatic(WalletLockStatusUtils.class)) {
            mockedStatic.when(() -> WalletLockStatusUtils.getErrorBasedOnWalletLockStatus(wallet))
                    .thenReturn(null)
                    .thenReturn(new ErrorDTO(ErrorConstants.WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorCode(), ErrorConstants.WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorMessage()));
            String expectedErrorMessage = ErrorConstants.WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorCode() + " --> " + ErrorConstants.WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorMessage();

            InvalidRequestException exception = assertThrows(InvalidRequestException.class, () ->
                    walletUnlockService.handleUnlock(wallet, invalidPin));

            assertEquals(ErrorConstants.WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorCode(), exception.getErrorCode());
            assertEquals(expectedErrorMessage, exception.getMessage());

            verify(walletUtil).decryptWalletKey(encryptedWalletKey, invalidPin);
            verify(walletLockService).enforceLockCyclePolicy(wallet);
            verify(walletLockService, times(1)).resetTemporaryLockIfExpired(wallet);
            mockedStatic.verify(() -> WalletLockStatusUtils.getErrorBasedOnWalletLockStatus(wallet), times(2));
            verify(walletLockService, never()).resetLockState(wallet);
            verify(walletRepository, times(1)).save(wallet);
        }
    }

    @Test
    void shouldThrowExceptionImmediatelyWhenUnlockingWalletIsAlreadyLockedPermanently() throws InvalidRequestException {
        when(walletLockService.resetTemporaryLockIfExpired(wallet)).thenReturn(wallet);

        try (MockedStatic<WalletLockStatusUtils> mockedStatic = mockStatic(WalletLockStatusUtils.class)) {
            mockedStatic.when(() -> WalletLockStatusUtils.getErrorBasedOnWalletLockStatus(wallet))
                    .thenReturn(new ErrorDTO(ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode(), ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorMessage()));
            String expectedErrorMessage = ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode() + " --> " + ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorMessage();

            WalletLockedException exception = assertThrows(WalletLockedException.class, () ->
                    walletUnlockService.handleUnlock(wallet, walletPin));

            assertEquals(ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode(), exception.getErrorCode());
            assertEquals(expectedErrorMessage, exception.getMessage());

            verify(walletLockService, times(1)).resetTemporaryLockIfExpired(wallet);
            mockedStatic.verify(() -> WalletLockStatusUtils.getErrorBasedOnWalletLockStatus(wallet), times(1));
        }
    }
}