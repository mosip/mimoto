package io.mosip.mimoto.service;

import io.mosip.mimoto.config.WalletPasscodeConfig;
import io.mosip.mimoto.config.WalletPasscodeConfigTest;
import io.mosip.mimoto.model.PasscodeControl;
import io.mosip.mimoto.model.Wallet;
import io.mosip.mimoto.model.WalletMetadata;
import io.mosip.mimoto.model.WalletStatus;
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
        assertEquals(3600000L, walletPasscodeConfig.getRetryBlockedUntil(), "RetryBlockedUntil should be 3600000 ms");
        assertEquals(5, walletPasscodeConfig.getMaxFailedAttemptsAllowedPerCycle(), "MaxFailedAttemptsAllowedPerCycle should be 5");
        assertEquals(3, walletPasscodeConfig.getMaxLockCyclesAllowed(), "MaxLockCyclesAllowed should be 3");
    }

    @Test
    public void enforceLockCyclePolicyShouldTemporarilyLockWalletOnInvalidLastAttemptInCurrentCycle() {
        wallet.getWalletMetadata().getPasscodeControl().setCurrentAttemptCount(5);
        wallet.getWalletMetadata().getPasscodeControl().setCurrentCycleCount(1);

        Wallet updatedWallet = walletLockManager.enforceLockCyclePolicy(wallet);

        assertEquals(WalletStatus.TEMPORARILY_LOCKED, updatedWallet.getWalletMetadata().getStatus());
        assertNotNull(updatedWallet.getWalletMetadata().getPasscodeControl().getRetryBlockedUntil());
        assertTrue(updatedWallet.getWalletMetadata().getPasscodeControl().getRetryBlockedUntil() > System.currentTimeMillis());
    }

    @Test
    public void enforceLockCyclePolicyShouldPermanentlyLockWalletOnInvalidLastAttemptInLastCycle() {
        wallet.getWalletMetadata().getPasscodeControl().setCurrentAttemptCount(5);
        wallet.getWalletMetadata().getPasscodeControl().setCurrentCycleCount(3);

        Wallet updatedWallet = walletLockManager.enforceLockCyclePolicy(wallet);

        assertEquals(WalletStatus.PERMANENTLY_LOCKED, updatedWallet.getWalletMetadata().getStatus());
        assertNull(updatedWallet.getWalletMetadata().getPasscodeControl().getRetryBlockedUntil());
    }

    @Test
    public void enforceLockCyclePolicyShouldSetStatusToLastAttemptBeforeLockoutOnInvalidPenultimateAttempt() {
        wallet.getWalletMetadata().getPasscodeControl().setCurrentAttemptCount(4);
        wallet.getWalletMetadata().getPasscodeControl().setCurrentCycleCount(3);

        Wallet updatedWallet = walletLockManager.enforceLockCyclePolicy(wallet);

        assertEquals(WalletStatus.LAST_ATTEMPT_BEFORE_LOCKOUT, updatedWallet.getWalletMetadata().getStatus());
        assertNull(updatedWallet.getWalletMetadata().getPasscodeControl().getRetryBlockedUntil());
    }

    @Test
    public void testResetTemporaryLockIfLockIsExpired() {
        wallet.getWalletMetadata().setStatus(WalletStatus.TEMPORARILY_LOCKED);
        wallet.getWalletMetadata().getPasscodeControl().setRetryBlockedUntil(System.currentTimeMillis() - 1000);

        Wallet updatedWallet = walletLockManager.resetTemporaryLockIfExpired(wallet);

        assertEquals(WalletStatus.LOCK_EXPIRED, updatedWallet.getWalletMetadata().getStatus());
        assertEquals(0, updatedWallet.getWalletMetadata().getPasscodeControl().getCurrentAttemptCount());
        assertNull(updatedWallet.getWalletMetadata().getPasscodeControl().getRetryBlockedUntil());
    }

    @Test
    public void testResetTemporaryLockIfLockIsNotExpired() {
        wallet.getWalletMetadata().setStatus(WalletStatus.TEMPORARILY_LOCKED);
        wallet.getWalletMetadata().getPasscodeControl().setRetryBlockedUntil(System.currentTimeMillis() + 1000);

        Wallet updatedWallet = walletLockManager.resetTemporaryLockIfExpired(wallet);

        assertEquals(WalletStatus.TEMPORARILY_LOCKED, updatedWallet.getWalletMetadata().getStatus());
        assertNotNull(updatedWallet.getWalletMetadata().getPasscodeControl().getRetryBlockedUntil());
        assertEquals(wallet.getWalletMetadata().getPasscodeControl().getCurrentAttemptCount(),
                updatedWallet.getWalletMetadata().getPasscodeControl().getCurrentAttemptCount());
    }

    @Test
    public void testResetLockState() {
        wallet.getWalletMetadata().getPasscodeControl().setCurrentAttemptCount(6);
        wallet.getWalletMetadata().getPasscodeControl().setCurrentCycleCount(2);
        wallet.getWalletMetadata().setStatus(WalletStatus.TEMPORARILY_LOCKED);

        Wallet updatedWallet = walletLockManager.resetLockState(wallet);

        assertEquals(0, updatedWallet.getWalletMetadata().getPasscodeControl().getCurrentAttemptCount());
        assertEquals(0, updatedWallet.getWalletMetadata().getPasscodeControl().getCurrentCycleCount());
        assertNull(updatedWallet.getWalletMetadata().getPasscodeControl().getRetryBlockedUntil());
        assertNull(updatedWallet.getWalletMetadata().getStatus());
    }
}