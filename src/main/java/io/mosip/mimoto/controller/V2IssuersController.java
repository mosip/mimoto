package io.mosip.mimoto.controller;

import com.google.common.collect.Lists;
import com.google.gson.Gson;
import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.IssuerDTO;
import io.mosip.mimoto.dto.IssuersDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.dto.v2.IssuerSupportedCredentialsResponse;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.PlatformErrorMessages;
import io.mosip.mimoto.service.IdpService;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.service.V2IssuersService;
import io.mosip.mimoto.util.DateUtils;
import io.mosip.mimoto.util.Utilities;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.*;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static io.mosip.mimoto.exception.PlatformErrorMessages.*;
import static io.mosip.mimoto.exception.PlatformErrorMessages.INVALID_ISSUER_ID_EXCEPTION;

@RestController
@RequestMapping(value = "v2/issuers")
public class V2IssuersController {

    @Autowired
    V2IssuersService v2IssuersService;

    private final Logger logger = LoggerFactory.getLogger(V2IssuersController.class);

    private static final String ID = "mosip.mimoto.issuers";

    @Autowired
    IdpService idpService;

    @Autowired
    IssuersService issuersService;

    @Autowired
    Utilities utilities;


    @GetMapping
    public ResponseEntity<Object> getAllIssuers(@RequestParam(required = false) String search){
        ResponseWrapper<IssuersDTO> responseWrapper = new ResponseWrapper<>();
        responseWrapper.setId(ID);
        responseWrapper.setVersion("v2");
        responseWrapper.setResponsetime(DateUtils.getRequestTimeString());

        try {
            responseWrapper.setResponse(v2IssuersService.getAllIssuers(search));
        } catch (ApiNotAccessibleException | IOException e) {
            logger.error("Exception occurred while fetching issuers ", e);
            responseWrapper.setErrors(List.of(new ErrorDTO(API_NOT_ACCESSIBLE_EXCEPTION.getCode(), API_NOT_ACCESSIBLE_EXCEPTION.getMessage())));
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseWrapper);
        }

        return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
    }

    @GetMapping("/{issuer-id}/credentials-supported")
    public ResponseEntity<Object> getCredentialsSupportedForIssuer(@PathVariable("issuer-id") String issuerId,
                                                                   @RequestParam(required = false) String search) {
        ResponseWrapper<Object> responseWrapper = new ResponseWrapper<>();
        responseWrapper.setId(ID);
        responseWrapper.setVersion("v2");
        responseWrapper.setResponsetime(DateUtils.getRequestTimeString());
        IssuerSupportedCredentialsResponse credentialsSupported;
        try {
            credentialsSupported = v2IssuersService.getCredentialsSupported(issuerId, search);
        }catch (ApiNotAccessibleException | IOException exception){
            logger.error("Exception occurred while fetching issuers ", exception);
            responseWrapper.setErrors(List.of(new ErrorDTO(API_NOT_ACCESSIBLE_EXCEPTION.getCode(), API_NOT_ACCESSIBLE_EXCEPTION.getMessage())));
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseWrapper);
        }
        responseWrapper.setResponse(credentialsSupported);

        if (credentialsSupported.getSupportedCredentials().isEmpty()) {
            logger.error("invalid issuer id passed - {}", issuerId);
            responseWrapper.setErrors(List.of(new ErrorDTO(INVALID_ISSUER_ID_EXCEPTION.getCode(), INVALID_ISSUER_ID_EXCEPTION.getMessage())));
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(responseWrapper);
        }

        return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);
    }

    @GetMapping("/{issuer-id}/credentials/{credentials-supported-id}/download")
    public ResponseEntity generatePdfForVCCredentials(@RequestHeader("Bearer") String token,
                                                      @PathVariable("issuer-id") String issuerId,
                                                      @PathVariable("credentials-supported-id") String credentialsSupportedId) {

        try{
            ByteArrayInputStream inputStream =  v2IssuersService.generatePdfForVerifiableCredentials(token, issuerId, credentialsSupportedId);
            return ResponseEntity
                    .ok()
                    .contentType(MediaType.APPLICATION_PDF)
                    .header(HttpHeaders.CONTENT_DISPOSITION, "inline; filename=\"Test.pdf\"")
                    .body(new InputStreamResource(inputStream));
        }catch (Exception e){
            logger.error("Error at generating PDF", e);
        }
       return null;
    }


}
