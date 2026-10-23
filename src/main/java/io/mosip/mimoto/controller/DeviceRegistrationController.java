package io.mosip.mimoto.controller;

import com.nimbusds.jose.util.JSONObjectUtils;
import io.mosip.mimoto.constant.SwaggerLiteralConstants;
import io.mosip.mimoto.dto.device.DeviceNonceResponse;
import io.mosip.mimoto.dto.device.DeviceRegistrationRequest;
import io.mosip.mimoto.exception.DeviceAttestationException;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.service.device.DeviceNonceService;
import io.mosip.mimoto.service.device.DeviceRegistrationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/device")
@Tag(name = SwaggerLiteralConstants.DEVICE_NAME, description = SwaggerLiteralConstants.DEVICE_DESCRIPTION)
public class DeviceRegistrationController {

    private final DeviceNonceService nonceService;
    private final DeviceRegistrationService registrationService;

    public DeviceRegistrationController(DeviceNonceService nonceService, DeviceRegistrationService registrationService) {
        this.nonceService = nonceService;
        this.registrationService = registrationService;
    }

    @Operation(summary = SwaggerLiteralConstants.DEVICE_NONCE_SUMMARY, description = SwaggerLiteralConstants.DEVICE_NONCE_DESCRIPTION)
    @GetMapping(value = "/nonce", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<DeviceNonceResponse> nonce() {
        return ResponseEntity.ok()
                .header("Cache-Control", "no-store")
                .body(new DeviceNonceResponse(nonceService.issue(), nonceService.ttlSeconds()));
    }

    @Operation(summary = SwaggerLiteralConstants.DEVICE_REGISTER_SUMMARY, description = SwaggerLiteralConstants.DEVICE_REGISTER_DESCRIPTION)
    @PostMapping(value = "/register", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> register(@RequestBody DeviceRegistrationRequest request) {
        try {
            if (request.platform() == null || request.publicKeyJwk() == null) {
                throw new DeviceAttestationException(ErrorConstants.INVALID_REQUEST, "platform and public_key_jwk are required");
            }
            registrationService.register(request.platform(), request.nonce(),
                    JSONObjectUtils.toJSONString(request.publicKeyJwk()), request.integrityToken());
            return ResponseEntity.status(HttpStatus.CREATED).build();
        } catch (DeviceAttestationException e) {
            log.warn("Device registration rejected: {} ({})", e.getErrorCode(), e.getMessage());
            return error(e.getErrorCode());
        }
    }

    private static ResponseEntity<Object> error(String errorCode) {
        HttpStatus status = switch (errorCode) {
            case "server_unavailable" -> HttpStatus.SERVICE_UNAVAILABLE;
            case "device_revoked" -> HttpStatus.FORBIDDEN;
            default -> HttpStatus.BAD_REQUEST;
        };
        String description = Arrays.stream(ErrorConstants.values())
                .filter(e -> e.getErrorCode().equals(errorCode))
                .findFirst()
                .map(ErrorConstants::getErrorMessage)
                .orElse(ErrorConstants.INVALID_REQUEST.getErrorMessage());
        return ResponseEntity.status(status)
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("error", errorCode, "error_description", description));
    }
}
