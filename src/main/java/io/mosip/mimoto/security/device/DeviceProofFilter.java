package io.mosip.mimoto.security.device;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
import io.mosip.mimoto.config.device.DeviceAttestationProperties;
import io.mosip.mimoto.config.device.DeviceAttestationProperties.Mode;
import io.mosip.mimoto.exception.DeviceAttestationException;
import io.mosip.mimoto.exception.ErrorConstants;
import io.mosip.mimoto.service.device.DeviceProofVerifier;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

/**
 * Requires a valid device proof on get-token, depending on {@code wallet.device-attestation.mode}:
 * off passes every request through untouched, monitor verifies and records the outcome but never blocks,
 * enforce rejects requests whose proof does not verify.
 */
@Slf4j
public class DeviceProofFilter extends OncePerRequestFilter {

    public static final String PROOF_HEADER = "X-Inji-Device-Proof";
    static final String METRIC = "mimoto.device.proof";
    // Token request forms are small; this only bounds memory for the cached body
    private static final int MAX_BODY_BYTES = 64 * 1024;

    private final DeviceProofVerifier verifier;
    private final Mode mode;
    private final MeterRegistry meterRegistry;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public DeviceProofFilter(DeviceProofVerifier verifier, DeviceAttestationProperties properties, MeterRegistry meterRegistry) {
        this.verifier = verifier;
        this.mode = properties.getMode();
        this.meterRegistry = meterRegistry;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return mode == Mode.OFF || !"POST".equalsIgnoreCase(request.getMethod());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        CachedBodyRequest cached;
        try {
            cached = new CachedBodyRequest(request, MAX_BODY_BYTES);
        } catch (IOException e) {
            record("request_too_large");
            if (mode == Mode.ENFORCE) {
                reject(response, HttpStatus.PAYLOAD_TOO_LARGE, ErrorConstants.INVALID_REQUEST);
                return;
            }
            log.warn("Device proof not checked: {}", e.getMessage());
            chain.doFilter(request, response);
            return;
        }

        try {
            String device = verifier.verify(request.getHeader(PROOF_HEADER), request.getMethod(),
                    request.getRequestURI(), cached.body());
            record("valid");
            log.debug("Device proof accepted for {}", device);
        } catch (DeviceAttestationException e) {
            record(e.getErrorCode());
            log.warn("Device proof rejected ({} mode): {} ({})", mode, e.getErrorCode(), e.getMessage());
            if (mode == Mode.ENFORCE) {
                reject(response, HttpStatus.UNAUTHORIZED, errorFor(e.getErrorCode()));
                return;
            }
        } catch (RuntimeException e) {
            record("error");
            log.error("Device proof check failed ({} mode)", mode, e);
            if (mode == Mode.ENFORCE) {
                reject(response, HttpStatus.SERVICE_UNAVAILABLE, ErrorConstants.SERVER_UNAVAILABLE);
                return;
            }
        }
        chain.doFilter(cached, response);
    }

    private void record(String outcome) {
        if (meterRegistry != null) {
            meterRegistry.counter(METRIC, "mode", mode.name().toLowerCase(), "outcome", outcome).increment();
        }
    }

    private static ErrorConstants errorFor(String code) {
        for (ErrorConstants error : ErrorConstants.values()) {
            if (error.getErrorCode().equals(code)) {
                return error;
            }
        }
        return ErrorConstants.INVALID_DEVICE_PROOF;
    }

    private void reject(HttpServletResponse response, HttpStatus status, ErrorConstants error) throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getOutputStream(),
                Map.of("error", error.getErrorCode(), "error_description", error.getErrorMessage()));
    }
}
