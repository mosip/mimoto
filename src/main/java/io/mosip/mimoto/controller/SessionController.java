package io.mosip.mimoto.controller;

import io.mosip.mimoto.core.http.ResponseWrapper;
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
    public ResponseEntity<ResponseWrapper<String>> getSessionStatus(HttpServletRequest request) {
        try {
            HttpSession httpSession = request.getSession(false);
            log.info("Session: {}", httpSession);

            if (httpSession == null || httpSession.getAttribute("userId") == null) {
                throw new LoginSessionException(LOGIN_SESSION_EXCEPTION.getCode(), "The session is invalid or expired due to inactivity", HttpStatus.NOT_FOUND);
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


