package io.mosip.mimoto.model;

import com.fasterxml.jackson.annotation.JsonValue;

public enum WalletStatus {
    READY_FOR_UNLOCK("ready_for_unlock"),
    ACTIVE("active"),
    TEMPORARILY_LOCKED("wallet_temporarily_locked"),
    PERMANENTLY_LOCKED("wallet_permanently_locked");

    private final String value;

    WalletStatus(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }
}
