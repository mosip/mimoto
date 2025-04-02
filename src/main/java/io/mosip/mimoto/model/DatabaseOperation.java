package io.mosip.mimoto.model;

public enum DatabaseOperation {
    FETCHING("Fetching"),
    STORING("Storing");
    private final String operation;

    DatabaseOperation(String operation) {
        this.operation = operation;
    }

    public String getValue() {
        return operation;
    }
}
