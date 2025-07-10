package io.mosip.mimoto.model;

import lombok.Data;

@Data
public class PasscodeControl {
    private int failedAttemptCount = 0;
    private int currentCycleCount = 0;
    private Long retryBlockedUntil = null;
}