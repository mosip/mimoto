package io.mosip.residentapp.model;

import java.util.Map;

import lombok.Data;

@Data
public class Event {
    private String id; // uuid
    private String transactionId; // privided by the publisher.
    Type type;
    private String timestamp; // ISO format
    private String dataShareUri; // URL

    private Map<String, Object> data;

    // Getter Methods

    public String getId() {
        return id;
    }

    public String getTransactionId() {
        return transactionId;
    }

    public Type getType() {
        return type;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public String getDataShareUri() {
        return dataShareUri;
    }

    // Setter Methods

    public void setId(String id) {
        this.id = id;
    }

    public void setTransactionId(String transactionId) {
        this.transactionId = transactionId;
    }

    public void setType(Type typeObject) {
        this.type = typeObject;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    public void setDataShareUri(String dataShareUri) {
        this.dataShareUri = dataShareUri;
    }
}