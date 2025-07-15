package io.mosip.mimoto.service;

import io.mosip.mimoto.config.WalletPasscodeConfig;
import io.mosip.mimoto.config.WalletPasscodeConfigTest;
import io.mosip.mimoto.model.PasscodeControl;
import io.mosip.mimoto.model.Wallet;
import io.mosip.mimoto.model.WalletMetadata;
import io.mosip.mimoto.model.WalletLockStatus;
import io.mosip.mimoto.util.TestUtilities;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@RunWith(SpringRunner.class)
@ContextConfiguration(classes = {WalletPasscodeConfigTest.class, WalletLockManager.class})
@TestPropertySource(locations = "classpath:application-test.properties")
public class WalletLockManagerTest {

    @Autowired
    private WalletLockManager walletLockManager;

    @Autowired
    private WalletPasscodeConfig walletPasscodeConfig;

    private Wallet wallet;

    @Before
    public void setUp() {
        String userId = UUID.randomUUID().toString();
        PasscodeControl passcodeControl = TestUtilities.createPasscodeControl(0, 0, null);
        WalletMetadata walletMetadata = TestUtilities.createWalletMetadata("Test Wallet", passcodeControl, null);
        wallet = TestUtilities.createWallet(userId, "encryptedWalletKey", walletMetadata);
    }

    @Test
    public void testWalletPasscodeConfigInitialization() {
        assertNotNull(walletPasscodeConfig, "WalletPasscodeConfig should be initialized");
        assertEquals(60, walletPasscodeConfig.getRetryBlockedUntil(), "RetryBlockedUntil should be 60 minutes");
        assertEquals(5, walletPasscodeConfig.getMaxFailedAttemptsAllowedPerCycle(), "MaxFailedAttemptsAllowedPerCycle should be 5");
        assertEquals(3, walletPasscodeConfig.getMaxLockCyclesAllowed(), "MaxLockCyclesAllowed should be 3");
    }

    @Test
    public void enforceLockCyclePolicyShouldTemporarilyLockWalletOnInvalidLastAttemptInCurrentCycle() {
        wallet.getWalletMetadata().getPasscodeControl().setFailedAttemptCount(4);
        wallet.getWalletMetadata().getPasscodeControl().setCurrentCycleCount(1);

        Wallet updatedWallet = walletLockManager.enforceLockCyclePolicy(wallet);

        assertEquals(WalletLockStatus.TEMPORARILY_LOCKED, updatedWallet.getWalletMetadata().getLockStatus());
        assertNotNull(updatedWallet.getWalletMetadata().getPasscodeControl().getRetryBlockedUntil());
        assertTrue(updatedWallet.getWalletMetadata().getPasscodeControl().getRetryBlockedUntil() > System.currentTimeMillis());
    }

    @Test
    public void enforceLockCyclePolicyShouldPermanentlyLockWalletOnInvalidLastAttemptInLastCycle() {
        wallet.getWalletMetadata().getPasscodeControl().setFailedAttemptCount(4);
        wallet.getWalletMetadata().getPasscodeControl().setCurrentCycleCount(3);

        Wallet updatedWallet = walletLockManager.enforceLockCyclePolicy(wallet);

        assertEquals(WalletLockStatus.PERMANENTLY_LOCKED, updatedWallet.getWalletMetadata().getLockStatus());
        assertNull(updatedWallet.getWalletMetadata().getPasscodeControl().getRetryBlockedUntil());
    }

    @Test
    public void enforceLockCyclePolicyShouldSetStatusToLastAttemptBeforeLockoutOnInvalidPenultimateAttempt() {
        wallet.getWalletMetadata().getPasscodeControl().setFailedAttemptCount(3);
        wallet.getWalletMetadata().getPasscodeControl().setCurrentCycleCount(3);

        Wallet updatedWallet = walletLockManager.enforceLockCyclePolicy(wallet);

        assertEquals(WalletLockStatus.LAST_ATTEMPT_BEFORE_LOCKOUT, updatedWallet.getWalletMetadata().getLockStatus());
        assertNull(updatedWallet.getWalletMetadata().getPasscodeControl().getRetryBlockedUntil());
    }

    @Test
    public void testResetTemporaryLockIfLockIsExpired() {
        wallet.getWalletMetadata().setLockStatus(WalletLockStatus.TEMPORARILY_LOCKED);
        wallet.getWalletMetadata().getPasscodeControl().setRetryBlockedUntil(System.currentTimeMillis() - 1000);

        Wallet updatedWallet = walletLockManager.resetTemporaryLockIfExpired(wallet);

        assertEquals(WalletLockStatus.LOCK_EXPIRED, updatedWallet.getWalletMetadata().getLockStatus());
        assertEquals(0, updatedWallet.getWalletMetadata().getPasscodeControl().getFailedAttemptCount());
        assertNull(updatedWallet.getWalletMetadata().getPasscodeControl().getRetryBlockedUntil());
    }

    @Test
    public void testResetTemporaryLockIfLockIsNotExpired() {
        wallet.getWalletMetadata().setLockStatus(WalletLockStatus.TEMPORARILY_LOCKED);
        wallet.getWalletMetadata().getPasscodeControl().setRetryBlockedUntil(System.currentTimeMillis() + 1000);

        Wallet updatedWallet = walletLockManager.resetTemporaryLockIfExpired(wallet);

        assertEquals(WalletLockStatus.TEMPORARILY_LOCKED, updatedWallet.getWalletMetadata().getLockStatus());
        assertNotNull(updatedWallet.getWalletMetadata().getPasscodeControl().getRetryBlockedUntil());
        assertEquals(wallet.getWalletMetadata().getPasscodeControl().getFailedAttemptCount(),
                updatedWallet.getWalletMetadata().getPasscodeControl().getFailedAttemptCount());
    }

    @Test
    public void testResetLockState() {
        wallet.getWalletMetadata().getPasscodeControl().setFailedAttemptCount(6);
        wallet.getWalletMetadata().getPasscodeControl().setCurrentCycleCount(2);
        wallet.getWalletMetadata().setLockStatus(WalletLockStatus.TEMPORARILY_LOCKED);

        Wallet updatedWallet = walletLockManager.resetLockState(wallet);

        assertEquals(0, updatedWallet.getWalletMetadata().getPasscodeControl().getFailedAttemptCount());
        assertEquals(0, updatedWallet.getWalletMetadata().getPasscodeControl().getCurrentCycleCount());
        assertNull(updatedWallet.getWalletMetadata().getPasscodeControl().getRetryBlockedUntil());
        assertNull(updatedWallet.getWalletMetadata().getLockStatus());
    }
}