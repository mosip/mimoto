package io.mosip.mimoto.controller;

import io.mosip.mimoto.dto.ErrorDTO;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@Slf4j
@RestController
@RequestMapping(value = "/secure/user")
public class UserController {

    @GetMapping("/profile")
    public ResponseEntity<?> getUserProfile(Authentication authentication) { // Use Authentication object directly
        try {

            if (authentication == null || !authentication.isAuthenticated()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new ErrorDTO("UNAUTHORIZED", "User is not authenticated."));
            }

            String username = authentication.getName(); // Get username from Authentication

            String jsonResponse = String.format("{\"displayName\": \"%s\", \"profilePictureUrl\": \"%s\"}", username, null);
            return ResponseEntity.ok(jsonResponse);

        } catch (Exception exception) {
            log.error("Error retrieving user profile", exception);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorDTO("INTERNAL_SERVER_ERROR", "An internal server error occurred."));
        }
    }
}
