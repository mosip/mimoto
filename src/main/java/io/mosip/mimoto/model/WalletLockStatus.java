package io.mosip.mimoto.model;

import com.fasterxml.jackson.annotation.JsonValue;

public enum WalletLockStatus {
    // Indicates that the wallet is temporarily locked due to exceeding the maximum allowed failed attempts within a cycle. Unlocking will be possible after the lock duration expires.
    TEMPORARILY_LOCKED("temporarily_locked"),
    // Indicates that the wallet is permanently locked after exceeding the maximum allowed lock cycles. Unlocking the Wallet is no longer possible.
    PERMANENTLY_LOCKED("permanently_locked"),
    // Indicates that the wallet is in the last attempt before being permanently locked. This serves as a warning state.
    LAST_ATTEMPT_BEFORE_LOCKOUT("last_attempt_before_lockout"),
    // Indicates that the temporary lock has expired, and the wallet can now be accessed again.
    LOCK_EXPIRED("lock_expired");

    private final String value;

    WalletLockStatus(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }
}
