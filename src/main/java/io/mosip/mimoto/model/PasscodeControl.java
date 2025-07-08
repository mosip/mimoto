package io.mosip.mimoto.model;

import lombok.Data;

@Data
public class PasscodeControl {
    private Integer currentAttemptCount = 1;
    private Integer currentCycleCount = 1;
    private Long retryBlockedUntil = null;
}