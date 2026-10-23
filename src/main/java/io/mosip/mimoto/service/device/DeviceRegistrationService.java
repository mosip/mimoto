package io.mosip.mimoto.service.device;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import io.mosip.mimoto.exception.DeviceAttestationException;
import io.mosip.mimoto.model.DevicePlatform;
import io.mosip.mimoto.model.DeviceRegistration;
import io.mosip.mimoto.model.DeviceRegistrationStatus;
import io.mosip.mimoto.repository.DeviceRegistrationRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import static io.mosip.mimoto.exception.ErrorConstants.ATTESTATION_FAILED;
import static io.mosip.mimoto.exception.ErrorConstants.DEVICE_REVOKED;
import static io.mosip.mimoto.exception.ErrorConstants.INVALID_NONCE;
import static io.mosip.mimoto.exception.ErrorConstants.INVALID_REQUEST;

/**
 * Registers a wallet device key once its platform attestation is verified.
 * <p>
 * The attestation must have been requested for
 * {@code base64url(SHA-256(UTF-8(nonce + jwkThumbprint)))}, where nonce came from this mimoto and
 * jwkThumbprint is the RFC 7638 SHA-256 thumbprint of the key being registered. This binds the
 * platform's verdict to that key, so a genuine device's verdict cannot be reused for another key.
 */
@Slf4j
@Service
public class DeviceRegistrationService {

    private final DeviceNonceService nonceService;
    private final DeviceRegistrationRepository repository;
    private final Map<DevicePlatform, DeviceAttestationVerifier> verifiers;

    public DeviceRegistrationService(DeviceNonceService nonceService,
                                     DeviceRegistrationRepository repository,
                                     List<DeviceAttestationVerifier> verifiers) {
        this.nonceService = nonceService;
        this.repository = repository;
        this.verifiers = verifiers.stream()
                .collect(Collectors.toUnmodifiableMap(DeviceAttestationVerifier::platform, Function.identity()));
    }

    @Transactional
    public void register(DevicePlatform platform, String nonce, String publicKeyJwk, String attestation) {
        DeviceAttestationVerifier verifier = verifiers.get(platform);
        if (verifier == null) {
            throw new DeviceAttestationException(INVALID_REQUEST, "Unsupported platform: " + platform);
        }
        ECKey publicKey = parseDeviceKey(publicKeyJwk);
        String thumbprint = thumbprint(publicKey);

        // Consume before calling the platform so a replayed request never reaches Google
        if (!nonceService.consume(nonce)) {
            throw new DeviceAttestationException(INVALID_NONCE, "Registration nonce is unknown, expired or already used");
        }
        Map<String, Object> verdict = verifier.verify(attestation, integrityNonce(nonce, thumbprint));

        DeviceRegistration registration = repository.findById(thumbprint).orElse(null);
        if (registration == null) {
            registration = new DeviceRegistration();
            registration.setJwkThumbprint(thumbprint);
            registration.setPlatform(platform);
            registration.setPublicKeyJwk(publicKey.toJSONString());
            registration.setStatus(DeviceRegistrationStatus.ACTIVE);
        } else if (registration.getStatus() == DeviceRegistrationStatus.REVOKED) {
            throw new DeviceAttestationException(DEVICE_REVOKED, "Device key is revoked");
        }
        registration.setAttestationVerdict(verdict);
        repository.save(registration);
        log.info("Registered {} device key {}", platform, thumbprint);
    }

    /**
     * The value the platform attestation must be requested with for this nonce and key.
     */
    public static String integrityNonce(String nonce, String jwkThumbprint) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest((nonce + jwkThumbprint).getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    static ECKey parseDeviceKey(String publicKeyJwk) {
        JWK jwk;
        try {
            jwk = JWK.parse(publicKeyJwk);
        } catch (Exception e) {
            throw new DeviceAttestationException(INVALID_REQUEST, "public_key_jwk is not a valid JWK");
        }
        if (!(jwk instanceof ECKey ecKey) || !Curve.P_256.equals(ecKey.getCurve())) {
            throw new DeviceAttestationException(INVALID_REQUEST, "public_key_jwk must be an EC P-256 key");
        }
        if (jwk.isPrivate()) {
            throw new DeviceAttestationException(INVALID_REQUEST, "public_key_jwk must not contain private key material");
        }
        return ecKey.toPublicJWK();
    }

    static String thumbprint(ECKey key) {
        try {
            return key.computeThumbprint().toString();
        } catch (Exception e) {
            throw new DeviceAttestationException(ATTESTATION_FAILED, "Unable to compute the key thumbprint");
        }
    }
}
