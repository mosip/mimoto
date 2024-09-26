package io.mosip.mimoto.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.mimoto.dto.openid.presentation.PresentationDefinitionDTO;
import io.mosip.mimoto.dto.openid.presentation.PresentationRequestDTO;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.exception.InvalidCredentialResourceException;
import io.mosip.mimoto.exception.InvalidVerifierException;
import io.mosip.mimoto.exception.VPNotCreatedException;
import io.mosip.mimoto.service.PresentationService;
import io.mosip.mimoto.service.VerifierService;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

@RestController
public class PresentationController {

    @Autowired
    PresentationService presentationService;
    private final Logger logger = LoggerFactory.getLogger(PresentationController.class);

    @Value("${mosip.inji.ovp.error.redirect.url.pattern}")
    String injiOvpErrorRedirectUrlPattern;

    @Value("${mosip.inji.web.redirect.url}")
    String injiWebRedirectUrl;

    @Autowired
    VerifierService verifierService;

    @Autowired
    ObjectMapper objectMapper;

    @GetMapping("/authorize")
    public void performAuthorization(HttpServletResponse response,
                                     @RequestParam("response_type") String responseType,
                                     @RequestParam("resource") String resource,
                                     @RequestParam("presentation_definition") String presentationDefinition,
                                     @RequestParam("client_id") String clientId,
                                     @RequestParam("redirect_uri") String redirectUri ) throws IOException {
        try {
            logger.info("Started Presentation Authorization in the controller.");
            verifierService.validateVerifier(clientId, redirectUri);
            PresentationDefinitionDTO presentationDefinitionDTO = objectMapper.readValue(presentationDefinition, PresentationDefinitionDTO.class);
            PresentationRequestDTO presentationRequestDTO = PresentationRequestDTO.builder()
                    .responseType(responseType)
                    .resource(resource)
                    .presentationDefinition(presentationDefinitionDTO)
                    .clientId(clientId)
                    .redirectUri(redirectUri).build();
            String redirectString = presentationService.authorizePresentation(presentationRequestDTO);
            logger.info("Completed Presentation Authorization in the controller.");
            response.sendRedirect(redirectString);
        } catch( InvalidVerifierException exception){
            sendRedirect(response, injiWebRedirectUrl, exception.getErrorCode(), exception.getErrorText(), exception);
        } catch(VPNotCreatedException | InvalidCredentialResourceException exception){
            sendRedirect(response, redirectUri, exception.getErrorCode(), exception.getErrorText(), exception);
        } catch (Exception exception){
            sendRedirect(response, redirectUri, ErrorConstants.INTERNAL_SERVER_ERROR.getErrorCode(), ErrorConstants.INTERNAL_SERVER_ERROR.getErrorMessage(), exception);
        }
    }

    private void sendRedirect(HttpServletResponse response, String domain, String code, String message, Exception exception) throws IOException {
        logger.error("Exception Occurred in Authorizing the presentation : \n\t code - " + code + "\n\t message - " + message + "\n\t Trace - " + Arrays.toString(exception.getStackTrace()));
        String injiVerifyRedirectString = String.format(injiOvpErrorRedirectUrlPattern,
                domain,
                code,
                URLEncoder.encode(message, StandardCharsets.UTF_8));
        response.setStatus(302);
        response.sendRedirect(injiVerifyRedirectString);
    }
}
