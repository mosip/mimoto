package io.mosip.mimoto.exception;

import io.mosip.mimoto.dto.ErrorDTO;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

@ControllerAdvice
@ResponseBody
@Slf4j
public class GlobalExceptionHandler {
    @ExceptionHandler(Throwable.class)  // Catch-all for unexpected exceptions
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ErrorDTO handleGenericException(Exception ex) {
        log.error("An unexpected error occurred: {}", ex.getMessage(), ex);
        return new ErrorDTO(ErrorConstants.INTERNAL_SERVER_ERROR.getErrorCode(), ErrorConstants.INTERNAL_SERVER_ERROR.getErrorMessage());
    }

    @ExceptionHandler(DataAccessResourceFailureException.class)  // Catch-all for unexpected exceptions
    @ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
    public ErrorDTO handleDatabaseException(Exception ex) {
        log.error("Database error occurred: {}", ex.getMessage(), ex);
        return new ErrorDTO(ErrorConstants.DATABASE_CONNECTION_EXCEPTION.getErrorCode(), ErrorConstants.DATABASE_CONNECTION_EXCEPTION.getErrorMessage());
    }

    @ExceptionHandler(ExternalServiceUnavailableException.class)
    @ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
    public ErrorDTO handleExternalServiceUnavailable(ExternalServiceUnavailableException ex) {
        log.error("Connection to external service failed: {}", ex.getMessage(), ex);
        return new ErrorDTO(ex.getErrorCode(), ex.getMessage());
    }

    @ExceptionHandler(InvalidRequestException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ErrorDTO handleInvalidRequest(InvalidRequestException ex) {
        log.error("Invalid request parameters: {}", ex.getMessage(), ex);
        return new ErrorDTO(ex.getErrorCode(), ex.getMessage());
    }

}
