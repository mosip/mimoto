package io.mosip.residentapp.util;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.residentapp.controller.CredentialShareController;
import io.mosip.residentapp.dto.mosip.ErrorDTO;
import io.mosip.residentapp.dto.mosip.CredentialShareResponse;
import io.mosip.residentapp.exception.AccessDeniedException;
import io.mosip.residentapp.exception.BaseCheckedException;
import io.mosip.residentapp.exception.BaseUncheckedException;
import io.mosip.residentapp.exception.InvalidTokenException;

/**
 * The Class CredentialShareExceptionHandler.
 * 
 * @author M1048358 Alok
 */
@RestControllerAdvice(assignableTypes = CredentialShareController.class)
public class CredentialShareExceptionHandler {

    /** The Constant REG_PACKET_GENERATOR_SERVICE_ID. */
    private static final String REG_PRINT_SERVICE_ID = "mosip.print.service.id";

    /** The Constant REG_PACKET_GENERATOR_APPLICATION_VERSION. */
    private static final String REG_PRINT_SERVICE_VERSION = "mosip.print.application.version";

    /** The Constant DATETIME_PATTERN. */
    private static final String DATETIME_PATTERN = "mosip.print.datetime.pattern";

    /** The env. */
    @Autowired
    private Environment env;

    private Logger logger = LoggerUtil.getLogger(CredentialShareExceptionHandler.class);


    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<CredentialShareResponse> badRequest(MethodArgumentNotValidException ex) {
        return buildApiExceptionResponse((Exception) ex);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<CredentialShareResponse> accessDenied(AccessDeniedException e) {
        return buildApiExceptionResponse((Exception) e);
    }

    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<CredentialShareResponse> invalidToken(InvalidTokenException e) {
        return buildApiExceptionResponse((Exception) e);
    }

    /**
     * Builds the reg status exception response.
     *
     * @param ex
     *           the ex
     * @return the response entity
     */
    private ResponseEntity<CredentialShareResponse> buildApiExceptionResponse(Exception ex) {
        CredentialShareResponse response = new CredentialShareResponse();
        Throwable e = ex;

        if (Objects.isNull(response.getId())) {
            response.setId(env.getProperty(REG_PRINT_SERVICE_ID));
        }
        if (e instanceof BaseCheckedException) {
            List<String> errorCodes = ((BaseCheckedException) e).getCodes();
            List<String> errorTexts = ((BaseCheckedException) e).getErrorTexts();

            List<ErrorDTO> errors = errorTexts.parallelStream()
                    .map(errMsg -> new ErrorDTO(errorCodes.get(errorTexts.indexOf(errMsg)), errMsg)).distinct()
                    .collect(Collectors.toList());
            response.setErrors(errors);
        }
        if (e instanceof BaseUncheckedException) {
            List<String> errorCodes = ((BaseUncheckedException) e).getCodes();
            List<String> errorTexts = ((BaseUncheckedException) e).getErrorTexts();

            List<ErrorDTO> errors = errorTexts.parallelStream()
                    .map(errMsg -> new ErrorDTO(errorCodes.get(errorTexts.indexOf(errMsg)), errMsg)).distinct()
                    .collect(Collectors.toList());
            response.setErrors(errors);
        }
        response.setResponsetime(DateUtils.getUTCCurrentDateTimeString(env.getProperty(DATETIME_PATTERN)));
        response.setVersion(env.getProperty(REG_PRINT_SERVICE_VERSION));

        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(response);
    }

}