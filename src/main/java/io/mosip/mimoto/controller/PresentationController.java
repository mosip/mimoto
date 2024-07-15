package io.mosip.mimoto.controller;

import io.mosip.mimoto.dto.openid.presentation.PresentationRequestDTO;
import io.mosip.mimoto.service.PresentationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;

@RestController
public class PresentationController {

    @Autowired
    PresentationService presentationService;

    @GetMapping("/authorize")
    public void performAuthorization(HttpServletResponse response, @ModelAttribute PresentationRequestDTO presentationRequestDTO) throws Exception {
        try {
            String redirectString = presentationService.authorizePresentation(presentationRequestDTO);
            response.sendRedirect(redirectString);
        } catch (Exception exception){
            throw new Exception(exception.getMessage());
        }
    }


}
