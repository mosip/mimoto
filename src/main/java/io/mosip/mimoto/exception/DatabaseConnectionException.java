package io.mosip.mimoto.exception;

import io.mosip.mimoto.model.DatabaseEntity;
import io.mosip.mimoto.model.DatabaseOperation;
import org.springframework.http.HttpStatus;

public class DatabaseConnectionException extends BaseCheckedException {
    private final HttpStatus status;

    public DatabaseConnectionException(String code, String message, DatabaseEntity entity, DatabaseOperation flow, HttpStatus status) {
        super(code, String.format("%s while %s %s data %s the database", message, flow.getValue(), entity.getValue(), flow.getValue()=="fetching"? "from" : "into"));
        this.status = status;
    }

    public HttpStatus getStatus() {
        return status;
    }
}

