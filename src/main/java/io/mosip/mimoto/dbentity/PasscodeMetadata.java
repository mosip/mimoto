package io.mosip.mimoto.dbentity;

import lombok.Data;

@Data
public class PasscodeMetadata {
    private int failedRetryAttempts = 0;
    private int currentLockCycles = 0;
}

