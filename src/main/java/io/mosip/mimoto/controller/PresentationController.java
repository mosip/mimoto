package io.mosip.mimoto.controller;

import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.dto.ErrorDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationRequestDTO;
import io.mosip.mimoto.exception.InvalidCredentialResourceException;
import io.mosip.mimoto.exception.InvalidVerifierException;
import io.mosip.mimoto.exception.OpenIdErrorMessages;
import io.mosip.mimoto.exception.VPNotCreatedException;
import io.mosip.mimoto.service.PresentationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

@RestController
public class PresentationController {

    @Autowired
    PresentationService presentationService;
    private final Logger logger = LoggerFactory.getLogger(PresentationController.class);

    @Value("${mosip.inji.verify.error.redirect.url}")
    String injiVerifyErrorRedirectUrl;

    @GetMapping("/authorize")

    public ResponseEntity<Object> performAuthorization(HttpServletResponse response, @ModelAttribute PresentationRequestDTO presentationRequestDTO) throws IOException {
        response.setHeader("Access-Control-Allow-Origin", "*");
        try {
            logger.info("Started Presentation Authorization in the controller.");
            String redirectString = presentationService.authorizePresentation(presentationRequestDTO);
            logger.info("Completed Presentation Authorization in the controller.");
            response.sendRedirect(redirectString);
        } catch( InvalidVerifierException exception){
            logger.error("Exception Occurred in Authorizing the presentation" + exception);
            ErrorDTO errorDTO = ErrorDTO.builder()
                    .errorCode(exception.getErrorCode())
                    .errorMessage(exception.getMessage())
                    .build();
            ResponseWrapper<Object> responseWrapper = new ResponseWrapper<>();
            responseWrapper.setErrors(Collections.singletonList(errorDTO));
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseWrapper);
        } catch(VPNotCreatedException | InvalidCredentialResourceException exception){
            logger.error("Exception Occurred in Authorizing the presentation" + exception);
            String injiVerifyRedirectString = String.format(injiVerifyErrorRedirectUrl,
                    presentationRequestDTO.getRedirect_uri(),
                    exception.getErrorText(),
                    exception.getErrorCode());
            response.sendRedirect(injiVerifyRedirectString);
        } catch (Exception exception){
            logger.error("Exception Occurred in Authorizing the presentation" + exception);
            String injiVerifyRedirectString = String.format(injiVerifyErrorRedirectUrl,
                    presentationRequestDTO.getRedirect_uri(),
                    OpenIdErrorMessages.INTERNAL_SERVER_ERROR.getErrorCode(),
                    OpenIdErrorMessages.INTERNAL_SERVER_ERROR.getErrorMessage());
            response.sendRedirect(injiVerifyRedirectString);
        }
        return null;
    }
}
