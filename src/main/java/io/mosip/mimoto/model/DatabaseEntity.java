package io.mosip.mimoto.model;

public enum DatabaseEntity {
    USERMETADATA("User Metadata"),
    VERIFIABLECREDENTIAL("Verifiable Credential");

    private final String value;

    DatabaseEntity(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}