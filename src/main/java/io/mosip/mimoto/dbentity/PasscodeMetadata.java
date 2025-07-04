package io.mosip.mimoto.dbentity;

import lombok.Data;

@Data
public class PasscodeMetadata {
    private Integer currentAttemptCount = 1;
    private Integer currentCycleCount = 1;
    private Long retryBlockedUntil = null;
}