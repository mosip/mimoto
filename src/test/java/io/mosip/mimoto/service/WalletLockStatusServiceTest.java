package io.mosip.mimoto.service;

import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.model.PasscodeControl;
import io.mosip.mimoto.model.Wallet;
import io.mosip.mimoto.model.WalletMetadata;
import io.mosip.mimoto.model.WalletLockStatus;
import io.mosip.mimoto.util.TestUtilities;
import io.mosip.mimoto.util.WalletLockStatusUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

@RunWith(SpringRunner.class)
public class WalletLockStatusServiceTest {

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
        wallet.getWalletMetadata().setLockStatus(WalletLockStatus.TEMPORARILY_LOCKED);

        WalletLockStatus status = WalletLockStatusUtils.getWalletLockStatus(wallet);

        assertEquals(WalletLockStatus.TEMPORARILY_LOCKED, status);
    }

    @Test
    public void testGetErrorBasedOnWalletLockStatusShouldReturnErrorObjForPermanentlyLockedWallet() {
        wallet.getWalletMetadata().setLockStatus(WalletLockStatus.PERMANENTLY_LOCKED);

        ErrorDTO errorDTO = WalletLockStatusUtils.getErrorBasedOnWalletLockStatus(wallet);

        assertEquals(ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorCode(), errorDTO.getErrorCode());
        assertEquals(ErrorConstants.WALLET_PERMANENTLY_LOCKED.getErrorMessage(), errorDTO.getErrorMessage());
    }

    @Test
    public void testGetErrorBasedOnWalletLockStatusShouldReturnErrorObjForTemporarilyLockedWallet() {
        wallet.getWalletMetadata().setLockStatus(WalletLockStatus.TEMPORARILY_LOCKED);

        ErrorDTO errorDTO = WalletLockStatusUtils.getErrorBasedOnWalletLockStatus(wallet);

        assertEquals(ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorCode(), errorDTO.getErrorCode());
        assertEquals(ErrorConstants.WALLET_TEMPORARILY_LOCKED.getErrorMessage(), errorDTO.getErrorMessage());
    }

    @Test
    public void testGetErrorBasedOnWalletLockStatusShouldReturnErrorObjWhenOnlyOneAttemptLeftBeforePermanentLockout() {
        wallet.getWalletMetadata().setLockStatus(WalletLockStatus.LAST_ATTEMPT_BEFORE_LOCKOUT);

        ErrorDTO errorDTO = WalletLockStatusUtils.getErrorBasedOnWalletLockStatus(wallet);

        assertEquals(ErrorConstants.WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorCode(), errorDTO.getErrorCode());
        assertEquals(ErrorConstants.WALLET_LAST_ATTEMPT_BEFORE_LOCKOUT.getErrorMessage(), errorDTO.getErrorMessage());
    }
}
