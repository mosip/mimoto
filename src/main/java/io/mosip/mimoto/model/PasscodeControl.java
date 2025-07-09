package io.mosip.mimoto.model;

import lombok.Data;

@Data
public class PasscodeControl {
    private Integer currentAttemptCount = 0;
    private Integer currentCycleCount = 0;
    private Long retryBlockedUntil = null;
}