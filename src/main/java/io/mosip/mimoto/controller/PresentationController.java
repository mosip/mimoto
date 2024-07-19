package io.mosip.mimoto.controller;

import io.mosip.mimoto.dto.openid.presentation.PresentationRequestDTO;
import io.mosip.mimoto.exception.ApiNotAccessibleException;
import io.mosip.mimoto.exception.VPNotCreatedException;
import io.mosip.mimoto.service.PresentationService;
import io.mosip.mimoto.service.impl.PresentationServiceImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestController
public class PresentationController {

    @Autowired
    PresentationService presentationService;

    private final Logger logger = LoggerFactory.getLogger(PresentationController.class);

    @GetMapping("/authorize")
    public void performAuthorization(HttpServletResponse response, @ModelAttribute PresentationRequestDTO presentationRequestDTO) throws IOException, ApiNotAccessibleException {
        try {
            logger.info("Started Presentation Authorization in the controller.");
            String redirectString = presentationService.authorizePresentation(presentationRequestDTO);
            logger.info("Completed Presentation Authorization in the controller.");
            response.sendRedirect(redirectString);
        } catch (VPNotCreatedException | IOException | ApiNotAccessibleException exception){
            logger.error("Exception Occurred in Authorizing the presentation" + exception);
            throw exception;
        }
    }


}
