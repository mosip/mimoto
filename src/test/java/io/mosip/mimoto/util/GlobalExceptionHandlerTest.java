package io.mosip.mimoto.util;

import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.ExternalServiceUnavailableException;
import io.mosip.mimoto.exception.InvalidRequestException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.lang.reflect.Method;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

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
        assertEquals(errorMessage, result.getErrorMessage());

        // Verify ResponseStatus annotation
        Method method = GlobalExceptionHandler.class.getMethod("handleInvalidRequest", InvalidRequestException.class);
        ResponseStatus responseStatus = method.getAnnotation(ResponseStatus.class);
        assertNotNull(responseStatus);
        assertEquals(HttpStatus.BAD_REQUEST, responseStatus.value());
    }

    @Test
    public void handleHttpMessageNotReadableExceptionReturnsBadRequest() throws Exception {
        // Arrange
        HttpMessageNotReadableException ex = new HttpMessageNotReadableException("Invalid JSON format");
        String expectedErrorCode = ErrorConstants.INVALID_REQUEST.getErrorCode();
        String expectedErrorMessage = "Unable to process request body";

        // Act
        ErrorDTO result = globalExceptionHandler.handleHttpMessageNotReadableException(ex);

        // Assert
        assertEquals(expectedErrorCode, result.getErrorCode());
        assertEquals(expectedErrorMessage, result.getErrorMessage());

        // Verify ResponseStatus annotation
        Method method = GlobalExceptionHandler.class.getMethod("handleHttpMessageNotReadableException", HttpMessageNotReadableException.class);
        ResponseStatus responseStatus = method.getAnnotation(ResponseStatus.class);
        assertNotNull(responseStatus);
        assertEquals(HttpStatus.BAD_REQUEST, responseStatus.value());
    }

    @Test
    public void handleValidationExceptionReturnsBadRequest() throws Exception {
        // Arrange: create BindingResult with a field error
        Object target = new Object();
        org.springframework.validation.BeanPropertyBindingResult bindingResult =
                new org.springframework.validation.BeanPropertyBindingResult(target, "errorDTO");
        bindingResult.addError(new org.springframework.validation.FieldError("errorDTO", "errorCode", "errorCode is required"));

        // Create MethodParameter pointing to the handler's parameter to construct the exception
        java.lang.reflect.Method handlerMethod = GlobalExceptionHandler.class.getMethod("handleValidationException", org.springframework.web.bind.MethodArgumentNotValidException.class);
        org.springframework.core.MethodParameter methodParameter = new org.springframework.core.MethodParameter(handlerMethod, 0);

        org.springframework.web.bind.MethodArgumentNotValidException ex =
                new org.springframework.web.bind.MethodArgumentNotValidException(methodParameter, bindingResult);

        // Act
        org.springframework.http.ResponseEntity<io.mosip.mimoto.dto.ErrorDTO> response = globalExceptionHandler.handleValidationException(ex);

        // Assert
        org.junit.Assert.assertEquals(org.springframework.http.HttpStatus.BAD_REQUEST, response.getStatusCode());
        io.mosip.mimoto.dto.ErrorDTO body = response.getBody();
        org.junit.Assert.assertNotNull(body);
        org.junit.Assert.assertEquals("invalid_request", body.getErrorCode());
        org.junit.Assert.assertTrue(body.getErrorMessage().contains("errorCode"));
    }

}