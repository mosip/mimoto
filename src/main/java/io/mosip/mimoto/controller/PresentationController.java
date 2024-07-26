package io.mosip.mimoto.controller;

import io.mosip.mimoto.dto.openid.presentation.PresentationRequestDTO;
import io.mosip.mimoto.exception.InvalidCredentialResourceException;
import io.mosip.mimoto.exception.InvalidVerifierException;
import io.mosip.mimoto.exception.OpenIdErrorMessages;
import io.mosip.mimoto.exception.VPNotCreatedException;
import io.mosip.mimoto.service.PresentationService;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@RestController
public class PresentationController {

    @Autowired
    PresentationService presentationService;
    private final Logger logger = LoggerFactory.getLogger(PresentationController.class);

    @Value("${mosip.inji.verify.error.redirect.url}")
    String injiVerifyErrorRedirectUrl;

    @Value("${mosip.inji.web.redirect.url:https://injiweb.dev1.mosip.net/authorize}")
    String injiWebErrorRedirectUrl;

    @GetMapping("/authorize")
    public void performAuthorization(HttpServletResponse response, @ModelAttribute PresentationRequestDTO presentationRequestDTO) throws IOException {
        try {
            logger.info("Started Presentation Authorization in the controller.");
            String redirectString = presentationService.authorizePresentation(presentationRequestDTO);
            logger.info("Completed Presentation Authorization in the controller.");
            response.sendRedirect(redirectString);
        } catch( InvalidVerifierException exception){
            sendRedirect(response, injiWebErrorRedirectUrl, exception.getErrorCode(), exception.getErrorText());
        } catch(VPNotCreatedException | InvalidCredentialResourceException exception){
            sendRedirect(response, presentationRequestDTO.getRedirect_uri(), exception.getErrorCode(), exception.getErrorText());
        } catch (Exception exception){
            sendRedirect(response, presentationRequestDTO.getRedirect_uri(), OpenIdErrorMessages.INTERNAL_SERVER_ERROR.getErrorCode(), OpenIdErrorMessages.INTERNAL_SERVER_ERROR.getErrorMessage());
        }
    }

    private void sendRedirect(HttpServletResponse response, String domain, String code, String message) throws IOException {
        logger.error("Exception Occurred in Authorizing the presentation");
        String injiVerifyRedirectString = String.format(injiVerifyErrorRedirectUrl,
                domain,
                code,
                URLEncoder.encode(message, StandardCharsets.UTF_8));
        response.setStatus(302);
        response.sendRedirect(injiVerifyRedirectString);
    }
}
