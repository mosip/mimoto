package io.mosip.mimoto.service;

import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.InvalidRequestException;
import io.mosip.mimoto.exception.WalletStatusException;
import io.mosip.mimoto.model.PasscodeControl;
import io.mosip.mimoto.model.Wallet;
import io.mosip.mimoto.model.WalletMetadata;
import io.mosip.mimoto.model.WalletStatus;
import io.mosip.mimoto.util.TestUtilities;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@RunWith(SpringRunner.class)
public class WalletStatusServiceTest {

    private final WalletStatusService walletStatusService = new WalletStatusService();
    private Wallet wallet;

    @Before
    public void setUp() {
        String userId = UUID.randomUUID().toString();
        PasscodeControl passcodeControl = TestUtilities.createPasscodeControl(0, 0, null);
        WalletMetadata walletMetadata = TestUtilities.createWalletMetadata("Test Wallet", passcodeControl, null);
        wallet = TestUtilities.createWallet(userId, "encryptedWalletKey", walletMetadata);
    }

    @Test
    public void testGetWalletStatusShouldReturnWalletStatus() {
        wallet.getWalletMetadata().setStatus(WalletStatus.TEMPORARILY_LOCKED);

        WalletStatus status = walletStatusService.getWalletStatus(wallet);

        assertEquals(WalletStatus.TEMPORARILY_LOCKED, status);
    }

    @Test
    public void testValidateWalletStatusShouldThrowExceptionForPermanentlyLockedWallet() {
        wallet.getWalletMetadata().setStatus(WalletStatus.PERMANENTLY_LOCKED);
        String expectedErrorMsg = ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode() + " --> " + ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorMessage();

        WalletStatusException exception = assertThrows(WalletStatusException.class, () -> walletStatusService.validateWalletStatus(wallet));

        assertEquals(ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode(), exception.getErrorCode());
        assertEquals(expectedErrorMsg, exception.getMessage());
    }

    @Test
    public void testValidateWalletStatusShouldThrowExceptionForTemporarilyLockedWallet() {
        wallet.getWalletMetadata().setStatus(WalletStatus.TEMPORARILY_LOCKED);
        String expectedErrorMsg = ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorCode() + " --> " + ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorMessage();

        WalletStatusException exception = assertThrows(WalletStatusException.class, () -> walletStatusService.validateWalletStatus(wallet));

        assertEquals(ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorCode(), exception.getErrorCode());
        assertEquals(expectedErrorMsg, exception.getMessage());
    }

    @Test
    public void testValidateLastAttemptBeforeLockoutShouldThrowExceptionWhenOnlyOneAttemptLeftBeforePermanentLockout() {
        wallet.getWalletMetadata().setStatus(WalletStatus.LAST_ATTEMPT_BEFORE_LOCKOUT);
        String expectedErrorMsg = ErrorConstants.WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorCode() + " --> " + ErrorConstants.WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorMessage();

        InvalidRequestException exception = assertThrows(InvalidRequestException.class, () -> walletStatusService.validateLastAttemptBeforeLockout(wallet));

        assertEquals(ErrorConstants.WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorCode(), exception.getErrorCode());
        assertEquals(expectedErrorMsg, exception.getMessage());
    }
}
