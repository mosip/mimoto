package io.mosip.mimoto.model;

import com.fasterxml.jackson.annotation.JsonValue;

public enum WalletStatus {
    TEMPORARILY_LOCKED("temporarily_locked"),
    PERMANENTLY_LOCKED("permanently_locked"),
    LAST_ATTEMPT_BEFORE_LOCKOUT("last_attempt_before_lockout"),
    LOCK_EXPIRED("lock_expired");

    private final String value;

    WalletStatus(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }
}
