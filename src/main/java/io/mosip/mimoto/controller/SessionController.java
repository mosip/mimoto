package io.mosip.mimoto.controller;

import io.mosip.mimoto.exception.LoginSessionException;
import io.mosip.mimoto.util.Utilities;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static io.mosip.mimoto.exception.PlatformErrorMessages.LOGIN_SESSION_EXCEPTION;

@RestController
@RequestMapping("/session")
@Slf4j
public class SessionController {
    @GetMapping("/status")
    public ResponseEntity<?> getSessionStatus(HttpServletRequest request) {
        try {
            HttpSession httpSession = request.getSession(false);

            if (httpSession == null || httpSession.getAttribute("userId") == null) {
                throw new LoginSessionException(LOGIN_SESSION_EXCEPTION.getCode(), "The session is invalid or expired due to inactivity", HttpStatus.NOT_FOUND);
            }

            return ResponseEntity.status(HttpStatus.OK).body("The session is valid and active");

        } catch (LoginSessionException exception) {
            log.error("Error occurred while retrieving session status: ", exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, LOGIN_SESSION_EXCEPTION.getCode(), exception.getStatus(), null);
        } catch (Exception exception) {
            log.error("Error occurred while retrieving session status: ", exception);
            return Utilities.getErrorResponseEntityWithoutWrapper(exception, LOGIN_SESSION_EXCEPTION.getCode(), HttpStatus.INTERNAL_SERVER_ERROR, null);
        }
    }
}


