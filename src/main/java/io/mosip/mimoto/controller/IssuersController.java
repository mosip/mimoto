package io.mosip.mimoto.controller;

import io.mosip.mimoto.constant.SwaggerLiteralConstants;
import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerConfigurationResponse;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.AuthorizationServerWellknownResponseException;
import io.mosip.mimoto.exception.InvalidIssuerIdException;
import io.mosip.mimoto.exception.InvalidWellknownResponseException;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.util.Utilities;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.List;

import static io.mosip.mimoto.exception.PlatformErrorMessages.API_NOT_ACCESSIBLE_EXCEPTION;
import static io.mosip.mimoto.exception.PlatformErrorMessages.INVALID_ISSUER_ID_EXCEPTION;

@RestController
@Slf4j
@RequestMapping(value = "/issuers")
@Tag(name = SwaggerLiteralConstants.ISSUERS_NAME, description = SwaggerLiteralConstants.ISSUERS_DESCRIPTION)
public class IssuersController {
    @Autowired
    IssuersService issuersService;

    @Autowired
    Utilities utilities;

    @Operation(summary = SwaggerLiteralConstants.ISSUERS_GET_ISSUERS_SUMMARY, description = SwaggerLiteralConstants.ISSUERS_GET_ISSUERS_DESCRIPTION)
    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ResponseWrapper<IssuersDTO>> getAllIssuers(@RequestParam(required = false, name = "search") String search) {
        ResponseWrapper<IssuersDTO> responseWrapper = new ResponseWrapper<>();
        try {
            responseWrapper.setResponse(issuersService.getIssuers(search));
        } catch (ApiNotAccessibleException | IOException | AuthorizationServerWellknownResponseException |
                 InvalidWellknownResponseException e) {
            log.error("Exception occurred while fetching issuers ", e);
            responseWrapper.setErrors(List.of(new ErrorDTO(API_NOT_ACCESSIBLE_EXCEPTION.getCode(), API_NOT_ACCESSIBLE_EXCEPTION.getMessage())));
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseWrapper);
        }

        return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
    }

    /**
     * @deprecated Since version 0.16.0, this endpoint is deprecated and will be removed in a future release.
     * Please use new endpoint {@link #getIssuerConfiguration(String)} instead.
     */
    @Deprecated(since = "0.16.0", forRemoval = true)
    @Operation(summary = SwaggerLiteralConstants.ISSUERS_GET_ISSUER_WELLKNOWN_SUMMARY, description = SwaggerLiteralConstants.ISSUERS_GET_ISSUER_WELLKNOWN_DESCRIPTION)
    @GetMapping(value = "/{issuer-id}/well-known-proxy", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<CredentialIssuerWellKnownResponse> getIssuerWellknown(@PathVariable("issuer-id") String issuerId) {
        try {
            CredentialIssuerConfigurationResponse issuerConfigurationResponse = issuersService.getIssuerConfiguration(issuerId);
            CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse = new CredentialIssuerWellKnownResponse(
                    issuerConfigurationResponse.getCredentialIssuer(),
                    issuerConfigurationResponse.getAuthorizationServers(),
                    issuerConfigurationResponse.getCredentialEndPoint(),
                    issuerConfigurationResponse.getCredentialConfigurationsSupported());
            return ResponseEntity.status(HttpStatus.OK).body(credentialIssuerWellKnownResponse);
        } catch (Exception exception) {
            log.error("Exception occurred while fetching issuers wellknown ", exception);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
        }
    }

    /**
     * @deprecated Since version 0.16.0, this endpoint is deprecated and will be removed in a future release.
     */
    @Deprecated(since = "0.16.0", forRemoval = true)
    @Operation(summary = SwaggerLiteralConstants.ISSUERS_GET_SPECIFIC_ISSUER_SUMMARY, description = SwaggerLiteralConstants.ISSUERS_GET_SPECIFIC_ISSUER_DESCRIPTION)
    @GetMapping(value = "/{issuer-id}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ResponseWrapper<IssuerDTO>> getIssuerConfig(@PathVariable("issuer-id") String issuerId) {
        ResponseWrapper<IssuerDTO> responseWrapper = new ResponseWrapper<>();
        IssuerDTO issuerDTO;
        try {
            issuerDTO = issuersService.getIssuerDetails(issuerId);
            responseWrapper.setResponse(issuerDTO);
            return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
        } catch (InvalidIssuerIdException exception) {
            log.error("invalid issuer id passed - ", issuerId);
            responseWrapper.setErrors(List.of(new ErrorDTO(INVALID_ISSUER_ID_EXCEPTION.getCode(), INVALID_ISSUER_ID_EXCEPTION.getMessage())));
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(responseWrapper);
        } catch (Exception exception) {
            log.error("Exception occurred while fetching issuers ", exception);
            String[] errorObj = Utilities.handleExceptionWithErrorCode(exception);
            List<ErrorDTO> errors = Utilities.getErrors(errorObj[0], errorObj[1]);
            responseWrapper.setResponse(null);
            responseWrapper.setErrors(errors);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseWrapper);
        }
    }

    @Operation(summary = SwaggerLiteralConstants.ISSUERS_GET_ISSUER_CONFIGURATION_SUMMARY, description = SwaggerLiteralConstants.ISSUERS_GET_ISSUER_CONFIGURATION_DESCRIPTION)
    @GetMapping(value = "/{issuer-id}/configuration", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ResponseWrapper<CredentialIssuerConfigurationResponse>> getIssuerConfiguration(@PathVariable("issuer-id") String issuerId) {
        ResponseWrapper<CredentialIssuerConfigurationResponse> responseWrapper = new ResponseWrapper<>();
        try {
            CredentialIssuerConfigurationResponse issuerConfigurationResponse = issuersService.getIssuerConfiguration(issuerId);
            responseWrapper.setResponse(issuerConfigurationResponse);
            return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
        } catch (Exception exception) {
            log.error("Exception occurred while fetching issuers configurations - " + exception);
            String[] errorObj = Utilities.handleExceptionWithErrorCode(exception);
            List<ErrorDTO> errors = Utilities.getErrors(errorObj[0], errorObj[1]);
            responseWrapper.setResponse(null);
            responseWrapper.setErrors(errors);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseWrapper);
        }
    }
}
