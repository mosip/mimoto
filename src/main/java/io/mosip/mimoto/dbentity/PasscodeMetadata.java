package io.mosip.mimoto.dbentity;

import lombok.Data;

@Data
public class PasscodeMetadata {
    private int retryRemainingAttempts = 5;
    private int remainingLockCycles = 3;
}

