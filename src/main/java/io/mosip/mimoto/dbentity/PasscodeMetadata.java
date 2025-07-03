package io.mosip.mimoto.dbentity;

import lombok.Data;

@Data
public class PasscodeMetadata {
    private Integer failedAttempts = 0;
    private Integer currentLockCycle = 1;
}

