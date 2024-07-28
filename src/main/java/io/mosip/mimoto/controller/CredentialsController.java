package io.mosip.mimoto.controller;

import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.InvalidCredentialResourceException;
import io.mosip.mimoto.service.CredentialService;
import io.mosip.mimoto.service.IdpService;
import io.mosip.mimoto.service.IssuersService;
import io.mosip.mimoto.util.DateUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.List;
import java.util.Map;

import static io.mosip.mimoto.exception.PlatformErrorMessages.API_NOT_ACCESSIBLE_EXCEPTION;
import static io.mosip.mimoto.exception.PlatformErrorMessages.MIMOTO_PDF_SIGN_EXCEPTION;

@RestController
@RequestMapping(value="/credentials")
public class CredentialsController {

    private static final String ID = "mosip.mimoto.credentials";
    private final Logger logger = LoggerFactory.getLogger(CredentialsController.class);

    @Autowired
    IssuersService issuersService;

    @Autowired
    CredentialService credentialService;

    @Autowired
    IdpService idpService;

    @PostMapping("/download")
    public ResponseEntity<?> downloadCredentialAsPDF(
            @RequestParam Map<String, String> params) {

        ResponseWrapper<Object> responseWrapper = new ResponseWrapper<>();
        responseWrapper.setId(ID);
        responseWrapper.setVersion("v1");
        responseWrapper.setResponsetime(DateUtils.getRequestTimeString());

        try {
            String issuerId = params.get("issuer");
            String credentialType = params.get("credential");

            logger.info("Initiated Token Call");
            TokenResponseDTO response = credentialService.getTokenResponse(params, issuerId);

            logger.info("Initiated Download Credential Call");
            ByteArrayInputStream inputStream = credentialService.downloadCredentialAsPDF(issuerId, credentialType, response);

            return ResponseEntity
                    .ok()
                    .contentType(MediaType.APPLICATION_PDF)
                    .header(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, "Content-Disposition")
                    .body(new InputStreamResource(inputStream));
        } catch (ApiNotAccessibleException | IOException exception) {
            logger.error("Exception occurred while fetching credential types ", exception);
            responseWrapper.setErrors(List.of(new ErrorDTO(API_NOT_ACCESSIBLE_EXCEPTION.getCode(), API_NOT_ACCESSIBLE_EXCEPTION.getMessage())));
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseWrapper);
        } catch (InvalidCredentialResourceException invalidCredentialResourceException) {
            logger.error("Exception occurred while pushing the data to data share ", invalidCredentialResourceException);
            responseWrapper.setErrors(List.of(new ErrorDTO(invalidCredentialResourceException.getErrorCode(), invalidCredentialResourceException.getMessage())));
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseWrapper);
        } catch (Exception exception) {
            logger.error("Exception occurred while generating pdf ", exception);
            responseWrapper.setErrors(List.of(new ErrorDTO(MIMOTO_PDF_SIGN_EXCEPTION.getCode(), exception.getMessage())));
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseWrapper);
        }
    }

}
