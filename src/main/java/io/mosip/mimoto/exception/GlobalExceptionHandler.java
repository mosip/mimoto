package io.mosip.mimoto.exception;

import io.mosip.mimoto.dto.ErrorDTO;
import lombok.extern.slf4j.Slf4j;
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
        log.error("An unexpected error occurred: {}", ex.getMessage(), ex); // Log the full error
        return new ErrorDTO(HttpStatus.INTERNAL_SERVER_ERROR.name(), "An unexpected server error occurred.");
    }
}
