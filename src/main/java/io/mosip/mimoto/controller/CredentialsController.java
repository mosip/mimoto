package io.mosip.mimoto.controller;

import io.mosip.mimoto.constant.SwaggerLiteralConstants;
import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.idp.TokenResponseDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.InvalidCredentialResourceException;
import io.mosip.mimoto.exception.VCVerificationException;
import io.mosip.mimoto.service.CredentialService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.List;
import java.util.Map;

import static io.mosip.mimoto.exception.PlatformErrorMessages.API_NOT_ACCESSIBLE_EXCEPTION;
import static io.mosip.mimoto.exception.PlatformErrorMessages.MIMOTO_PDF_SIGN_EXCEPTION;

@RestController
@RequestMapping(value="/credentials")
@Slf4j
@Tag( name = SwaggerLiteralConstants.CREDENTIALS_NAME, description = SwaggerLiteralConstants.CREDENTIALS_DESCRIPTION)
public class CredentialsController {

    @Autowired
    CredentialService credentialService;

    @Operation( summary = SwaggerLiteralConstants.CREDENTIALS_DOWNLOAD_VC_SUMMARY, description = SwaggerLiteralConstants.CREDENTIALS_DOWNLOAD_VC_DESCRIPTION)
    @ApiResponses({
            @ApiResponse(responseCode = "200", content = { @Content(mediaType = "application/pdf") }),
            @ApiResponse(responseCode = "400",content = { @Content(schema = @Schema(implementation = ResponseWrapper.class), mediaType = "application/json") }) })
    @PostMapping("/download")
    public ResponseEntity<?> downloadCredentialAsPDF(@RequestParam Map<String, String> params ) {
        ResponseWrapper<Object> responseWrapper = new ResponseWrapper<>();

        try {
            String issuerId = params.get("issuer");
            String credentialType = params.get("credential");
            String credentialValidity = params.get("vcStorageExpiryLimitInTimes");

            log.info("Initiated Token Call");
            TokenResponseDTO response = credentialService.getTokenResponse(params, issuerId);

            log.info("Initiated Download Credential Call");
            ByteArrayInputStream inputStream = credentialService.downloadCredentialAsPDF(issuerId, credentialType, response, credentialValidity);

            return ResponseEntity
                    .ok()
                    .contentType(MediaType.APPLICATION_PDF)
                    .header(HttpHeaders.ACCESS_CONTROL_EXPOSE_HEADERS, "Content-Disposition")
                    .body(new InputStreamResource(inputStream));
        } catch (ApiNotAccessibleException | IOException exception) {
            log.error("Exception occurred while fetching credential types ", exception);
            responseWrapper.setErrors(List.of(new ErrorDTO(API_NOT_ACCESSIBLE_EXCEPTION.getCode(), API_NOT_ACCESSIBLE_EXCEPTION.getMessage())));
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseWrapper);
        } catch (InvalidCredentialResourceException invalidCredentialResourceException) {
            log.error("Exception occurred while pushing the data to data share ", invalidCredentialResourceException);
            responseWrapper.setErrors(List.of(new ErrorDTO(invalidCredentialResourceException.getErrorCode(), invalidCredentialResourceException.getMessage())));
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseWrapper);
        } catch (VCVerificationException exception) {
            log.error("Exception occurred while verification of the verifiable Credential", exception);
            responseWrapper.setErrors(List.of(new ErrorDTO(exception.getErrorCode(), exception.getMessage())));
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseWrapper);
        } catch (Exception exception) {
            log.error("Exception occurred while generating pdf ", exception);
            responseWrapper.setErrors(List.of(new ErrorDTO(MIMOTO_PDF_SIGN_EXCEPTION.getCode(), exception.getMessage())));
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseWrapper);
        }
    }
}
