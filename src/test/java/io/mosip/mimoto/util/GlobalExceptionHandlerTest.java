package io.mosip.mimoto.exception;

import io.mosip.mimoto.dto.ErrorDTO;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.lang.reflect.Method;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class GlobalExceptionHandlerTest {

    @InjectMocks
    private GlobalExceptionHandler globalExceptionHandler;

    @Before
    public void setUp() {
        // Initialize any mocks if needed
    }

    @Test
    public void handleGenericExceptionReturnsInternalServerError() throws Exception {
        // Arrange
        Exception ex = new RuntimeException("Unexpected error");
        String expectedErrorCode = ErrorConstants.INTERNAL_SERVER_ERROR.getErrorCode();
        String expectedErrorMessage = ErrorConstants.INTERNAL_SERVER_ERROR.getErrorMessage();

        // Act
        ErrorDTO result = globalExceptionHandler.handleGenericException(ex);

        // Assert
        assertEquals(expectedErrorCode, result.getErrorCode());
        assertEquals(expectedErrorMessage, result.getErrorMessage());

        // Verify ResponseStatus annotation
        Method method = GlobalExceptionHandler.class.getMethod("handleGenericException", Exception.class);
        ResponseStatus responseStatus = method.getAnnotation(ResponseStatus.class);
        assertNotNull(responseStatus);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, responseStatus.value());
    }

    @Test
    public void handleDatabaseExceptionReturnsServiceUnavailable() throws Exception {
        // Arrange
        DataAccessResourceFailureException ex = new DataAccessResourceFailureException("Database connection failed");
        String expectedErrorCode = ErrorConstants.DATABASE_CONNECTION_EXCEPTION.getErrorCode();
        String expectedErrorMessage = ErrorConstants.DATABASE_CONNECTION_EXCEPTION.getErrorMessage();

        // Act
        ErrorDTO result = globalExceptionHandler.handleDatabaseException(ex);

        // Assert
        assertEquals(expectedErrorCode, result.getErrorCode());
        assertEquals(expectedErrorMessage, result.getErrorMessage());

        // Verify ResponseStatus annotation
        Method method = GlobalExceptionHandler.class.getMethod("handleDatabaseException", Exception.class);
        ResponseStatus responseStatus = method.getAnnotation(ResponseStatus.class);
        assertNotNull(responseStatus);
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, responseStatus.value());
    }

    @Test
    public void handleExternalServiceUnavailableReturnsServiceUnavailable() throws Exception {
        // Arrange
        String errorCode = "EXT_SERVICE_ERROR";
        String errorMessage = "EXT_SERVICE_ERROR --> External service unavailable";
        ExternalServiceUnavailableException ex = new ExternalServiceUnavailableException(errorCode, errorMessage);

        // Act
        ErrorDTO result = globalExceptionHandler.handleExternalServiceUnavailable(ex);

        // Assert
        assertEquals(errorCode, result.getErrorCode());
        assertEquals(errorCode + " --> " + errorMessage, result.getErrorMessage());

        // Verify ResponseStatus annotation
        Method method = GlobalExceptionHandler.class.getMethod("handleExternalServiceUnavailable", ExternalServiceUnavailableException.class);
        ResponseStatus responseStatus = method.getAnnotation(ResponseStatus.class);
        assertNotNull(responseStatus);
        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, responseStatus.value());
    }

    @Test
    public void handleInvalidRequestReturnsBadRequest() throws Exception {
        // Arrange
        String errorCode = "INVALID_REQUEST";
        String errorMessage = "Invalid input provided";
        InvalidRequestException ex = new InvalidRequestException(errorCode, errorMessage);

        // Act
        ErrorDTO result = globalExceptionHandler.handleInvalidRequest(ex);

        // Assert
        assertEquals(errorCode, result.getErrorCode());
        assertEquals(errorCode + " --> " + errorMessage, result.getErrorMessage());

        // Verify ResponseStatus annotation
        Method method = GlobalExceptionHandler.class.getMethod("handleInvalidRequest", InvalidRequestException.class);
        ResponseStatus responseStatus = method.getAnnotation(ResponseStatus.class);
        assertNotNull(responseStatus);
        assertEquals(HttpStatus.BAD_REQUEST, responseStatus.value());
    }
}