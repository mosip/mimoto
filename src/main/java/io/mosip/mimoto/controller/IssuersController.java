package io.mosip.mimoto.controller;

import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.dto.DisplayDTO;
import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.dto.mimoto.*;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.util.DateUtils;
import io.mosip.mimoto.util.RestApiClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.List;
import java.util.Optional;

import static io.mosip.mimoto.exception.PlatformErrorMessages.*;
import static io.mosip.mimoto.util.Utilities.handleExceptionWithErrorCode;

@RestController
@RequestMapping(value = "/issuers")
public class IssuersController {
    @Autowired
    IssuersService issuersService;

    @Autowired
    private RestApiClient restApiClient;

    private static final String defaultLanguageConstant = "en";

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

    @GetMapping("/{issuer-id}")
    public ResponseEntity<Object> getIssuerConfig(@PathVariable("issuer-id") String issuerId) {
        ResponseWrapper<Object> responseWrapper = new ResponseWrapper<>();
        responseWrapper.setId(ID);
        responseWrapper.setVersion("v1");
        responseWrapper.setResponsetime(DateUtils.getRequestTimeString());

        IssuerDTO issuerConfig;
        try {
            issuerConfig = issuersService.getIssuerConfig(issuerId);
        } catch (Exception exception ) {
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
            credentialTypes = issuersService.getCredentialsSupported(issuerId, search);
        }catch (ApiNotAccessibleException | IOException exception){
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

    @PostMapping("/{issuer-id}/credentials/{credentialType}/download")
    public ResponseEntity<?> downloadCredentialAsPDF(
            @RequestHeader("Authorization") String token,
            @PathVariable("issuer-id") String issuerId,
            @PathVariable("credentialType") String credentialType,
            @RequestBody VCCredentialRequest vcCredentialRequest) {

        ResponseWrapper<Object> responseWrapper = new ResponseWrapper<>();
        responseWrapper.setId(ID);
        responseWrapper.setVersion("v1");
        responseWrapper.setResponsetime(DateUtils.getRequestTimeString());

        try{
            IssuerDTO issuerConfig = issuersService.getIssuerConfig(issuerId);
            logger.info("issuerConfig => " +  issuerConfig);
            CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse = issuersService.getCredentialIssuerWellknown(issuerId, credentialType);
            logger.info("Wellknown => " +  credentialIssuerWellKnownResponse);
            CredentialsSupportedResponse credentialsSupportedResponse = issuersService.getCredentialSupported(credentialIssuerWellKnownResponse, credentialType);
            VCCredentialResponse vcCredentialResponse = issuersService.downloadCredential(credentialIssuerWellKnownResponse.getCredentialEndPoint(), vcCredentialRequest, token);
            logger.info("vcCredentialResponse" + vcCredentialResponse);
            ByteArrayInputStream inputStream =  issuersService.generatePdfForVerifiableCredentials(vcCredentialResponse, issuerConfig, credentialsSupportedResponse, credentialIssuerWellKnownResponse.getCredentialEndPoint());
            return ResponseEntity
                    .ok()
                    .contentType(MediaType.APPLICATION_PDF)
                    .header(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, "Content-Disposition")
                    .body(new InputStreamResource(inputStream));
        }catch (ApiNotAccessibleException | IOException exception){
            logger.error("Exception occurred while fetching credential types ", exception);
            responseWrapper.setErrors(List.of(new ErrorDTO(API_NOT_ACCESSIBLE_EXCEPTION.getCode(), API_NOT_ACCESSIBLE_EXCEPTION.getMessage())));
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseWrapper);
        } catch (Exception exception) {
            logger.error("Exception occurred while generating pdf ", exception);
            responseWrapper.setErrors(List.of(new ErrorDTO(MIMOTO_PDF_SIGN_EXCEPTION.getCode(), MIMOTO_PDF_SIGN_EXCEPTION.getMessage())));
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseWrapper);
        }
    }

}
