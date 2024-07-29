package io.mosip.mimoto.controller;

import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.dto.mimoto.IssuerSupportedCredentialsResponse;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.service.CredentialService;
import io.mosip.mimoto.service.IdpService;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.util.DateUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.List;

import static io.mosip.mimoto.exception.PlatformErrorMessages.API_NOT_ACCESSIBLE_EXCEPTION;
import static io.mosip.mimoto.exception.PlatformErrorMessages.INVALID_ISSUER_ID_EXCEPTION;
import static io.mosip.mimoto.util.Utilities.handleExceptionWithErrorCode;

@RestController
@RequestMapping(value = "/issuers")
public class IssuersController {
    @Autowired
    IssuersService issuersService;

    @Autowired
    IdpService idpService;

    @Autowired
    CredentialService credentialService;

    private static final String ID = "mosip.mimoto.issuers";

    private final Logger logger = LoggerFactory.getLogger(IssuersController.class);

    @GetMapping()
    public ResponseEntity<Object> getAllIssuers(@RequestParam(required = false, name = "search") String search) {
        ResponseWrapper<IssuersDTO> responseWrapper = new ResponseWrapper<>();
        responseWrapper.setId(ID);
        responseWrapper.setVersion("v1");
        responseWrapper.setResponsetime(DateUtils.getRequestTimeString());
        try {
            responseWrapper.setResponse(issuersService.getAllIssuers(search));
        } catch (ApiNotAccessibleException | IOException e) {
            logger.error("Exception occurred while fetching issuers ", e);
            responseWrapper.setErrors(List.of(new ErrorDTO(API_NOT_ACCESSIBLE_EXCEPTION.getCode(), API_NOT_ACCESSIBLE_EXCEPTION.getMessage())));
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseWrapper);
        }

        return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
    }

    @GetMapping("/{issuer-id}/.well-known")
    public ResponseEntity<Object> getIssuerWellknown(@PathVariable("issuer-id") String issuerId) {
        try {
            CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse = issuersService.getIssuerWellknown(issuerId);
            return ResponseEntity.status(HttpStatus.OK).body(credentialIssuerWellKnownResponse);
        } catch (Exception exception) {
            logger.error("Exception occurred while fetching issuers wellknown ", exception);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
        }
    }

    @GetMapping("/{issuer-id}")
    public ResponseEntity<Object> getIssuerConfig(@PathVariable("issuer-id") String issuerId) {
        ResponseWrapper<Object> responseWrapper = new ResponseWrapper<>();
        responseWrapper.setId(ID);
        responseWrapper.setVersion("v1");
        responseWrapper.setResponsetime(DateUtils.getRequestTimeString());

        IssuerDTO issuerConfig;
        try {
            issuerConfig = issuersService.getIssuerConfig(issuerId);
        } catch (Exception exception) {
            logger.error("Exception occurred while fetching issuers ", exception);
            responseWrapper = handleExceptionWithErrorCode(exception);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseWrapper);
        }

        responseWrapper.setResponse(issuerConfig);

        if (issuerConfig == null) {
            logger.error("invalid issuer id passed - {}", issuerId);
            responseWrapper.setErrors(List.of(new ErrorDTO(INVALID_ISSUER_ID_EXCEPTION.getCode(), INVALID_ISSUER_ID_EXCEPTION.getMessage())));
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(responseWrapper);
        }

        return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
    }

    @GetMapping("/{issuer-id}/credentialTypes")
    public ResponseEntity<Object> getCredentialTypes(@PathVariable("issuer-id") String issuerId,
                                                     @RequestParam(required = false, name = "search") String search) {
        ResponseWrapper<Object> responseWrapper = new ResponseWrapper<>();
        responseWrapper.setId(ID);
        responseWrapper.setVersion("v1");
        responseWrapper.setResponsetime(DateUtils.getRequestTimeString());
        IssuerSupportedCredentialsResponse credentialTypes;
        try {
            credentialTypes = credentialService.getCredentialsSupported(issuerId, search);
        } catch (ApiNotAccessibleException | IOException exception) {
            logger.error("Exception occurred while fetching credential types", exception);
            responseWrapper.setErrors(List.of(new ErrorDTO(API_NOT_ACCESSIBLE_EXCEPTION.getCode(), API_NOT_ACCESSIBLE_EXCEPTION.getMessage())));
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseWrapper);
        }
        responseWrapper.setResponse(credentialTypes);

        if (credentialTypes.getSupportedCredentials() == null) {
            logger.error("invalid issuer id passed - {}", issuerId);
            responseWrapper.setErrors(List.of(new ErrorDTO(INVALID_ISSUER_ID_EXCEPTION.getCode(), INVALID_ISSUER_ID_EXCEPTION.getMessage())));
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(responseWrapper);
        }

        return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
    }

}
