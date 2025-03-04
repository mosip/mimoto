package io.mosip.mimoto.controller;

import io.mosip.mimoto.core.http.ResponseWrapper;
import io.mosip.mimoto.exception.LoginSessionException;
import io.mosip.mimoto.util.Utilities;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Enumeration;
import java.util.Map;

import static io.mosip.mimoto.exception.PlatformErrorMessages.LOGIN_SESSION_EXCEPTION;

@RestController
@RequestMapping("/session")
@Slf4j
public class SessionController {
    @GetMapping("/status")
    public ResponseEntity<ResponseWrapper<String>> getSessionStatus(HttpSession httpSession) {
        try {
            log.info("Session: {}", httpSession);

            if (httpSession == null) {
                throw new LoginSessionException("UNAUTHORIZED", "Session is expired, please log in again", HttpStatus.UNAUTHORIZED);
            }

            ResponseWrapper<String> responseWrapper = new ResponseWrapper<>();
            responseWrapper.setResponse("Session is active");
            return ResponseEntity.status(HttpStatus.OK).body(responseWrapper);

        } catch (LoginSessionException exception) {
            log.error("Error occurred while retrieving session status: ", exception);
            return Utilities.handleErrorResponse(exception, LOGIN_SESSION_EXCEPTION.getCode(), exception.getStatus(), null);
        } catch (Exception exception) {
            log.error("Error occurred while retrieving session status: ", exception);
            return Utilities.handleErrorResponse(exception, LOGIN_SESSION_EXCEPTION.getCode(), HttpStatus.INTERNAL_SERVER_ERROR, null);
        }
    }
}


