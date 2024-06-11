package io.mosip.mimoto.controller;

import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.dto.DisplayDTO;
import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.dto.mimoto.CredentialIssuerWellKnownResponse;
import io.mosip.mimoto.dto.mimoto.CredentialSupportedDisplayResponse;
import io.mosip.mimoto.dto.mimoto.CredentialsSupportedResponse;
import io.mosip.mimoto.dto.mimoto.IssuerSupportedCredentialsResponse;
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

    @GetMapping("/{issuer-id}/credentials/{credentialType}/download")
    public ResponseEntity<?> generatePdfForVC(@RequestHeader("Bearer") String token,
                                                         @PathVariable("issuer-id") String issuerId,
                                                         @PathVariable("credentialType") String credentialType) {

        ResponseWrapper<Object> responseWrapper = new ResponseWrapper<>();
        responseWrapper.setId(ID);
        responseWrapper.setVersion("v1");
        responseWrapper.setResponsetime(DateUtils.getRequestTimeString());

        try{
            IssuerDTO issuerConfig = issuersService.getIssuerConfig(issuerId);
            CredentialIssuerWellKnownResponse credentialIssuerWellKnownResponse = restApiClient.getApi(issuerConfig.getWellKnownEndpoint(), CredentialIssuerWellKnownResponse.class);
            if (credentialIssuerWellKnownResponse == null) {
                throw new ApiNotAccessibleException();
            }
            Optional<CredentialsSupportedResponse> credentialsSupportedResponse = credentialIssuerWellKnownResponse.getCredentialsSupported().stream()
                    .filter(credentialsSupported -> credentialsSupported.getId().equals(credentialType))
                    .findFirst();
            if (credentialsSupportedResponse.isEmpty()){
                logger.error("Invalid credential Type passed - {}", credentialType);
                responseWrapper.setErrors(List.of(new ErrorDTO(INVALID_CREDENTIAL_TYPE_EXCEPTION.getCode(), INVALID_CREDENTIAL_TYPE_EXCEPTION.getMessage())));
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseWrapper);
            }
            ByteArrayInputStream inputStream =  issuersService.generatePdfForVerifiableCredentials(token, issuerConfig, credentialsSupportedResponse.get(), credentialIssuerWellKnownResponse.getCredentialEndPoint());
            //PDF file name with issuer display name and credential type display name
            String pdfFileName = issuerConfig.getDisplay().stream().filter(displayDTO -> defaultLanguageConstant.equals(displayDTO.getLanguage())).map(DisplayDTO::getName).findFirst().orElse(null) +
                    "_" + credentialsSupportedResponse.get().getDisplay().stream()
                    .filter(credentialSupportedDisplayResponse -> defaultLanguageConstant.equals(credentialSupportedDisplayResponse.getLocale())).map(CredentialSupportedDisplayResponse::getName).findFirst().orElse(null);
            return ResponseEntity
                    .ok()
                    .contentType(MediaType.APPLICATION_PDF)
                    .header(HttpHeaders.CONTENT_DISPOSITION, String.format("attachment; filename=%s.pdf", pdfFileName))
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
