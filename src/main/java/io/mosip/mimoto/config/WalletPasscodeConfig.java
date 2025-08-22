package io.mosip.mimoto.config;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Slf4j
@Getter
@Setter
@ConfigurationProperties(prefix = "wallet.passcode")
public class WalletPasscodeConfig {
    private long retryBlockedUntil = 30000;
    private int maxFailedAttemptsAllowedPerCycle = 1;
    private int maxLockCyclesAllowed = 1;

    @PostConstruct
    public void validateAndCorrectDefaults() {
        if (maxLockCyclesAllowed <= 0) {
            log.warn("Invalid value for maxLockCyclesAllowed: {}. It must be > 0. Setting to default: 1", maxLockCyclesAllowed);
            maxLockCyclesAllowed = 1;
        }

        if (maxFailedAttemptsAllowedPerCycle <= 0) {
            log.warn("Invalid value for maxFailedAttemptsAllowedPerCycle: {}. It must be > 0. Setting to default: 1", maxFailedAttemptsAllowedPerCycle);
            maxFailedAttemptsAllowedPerCycle = 1;
        }
    }
}
