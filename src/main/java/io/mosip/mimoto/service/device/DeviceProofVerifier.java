package io.mosip.mimoto.service.device;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.mosip.mimoto.config.device.DeviceAttestationProperties;
import io.mosip.mimoto.exception.DeviceAttestationException;
import io.mosip.mimoto.model.DeviceRegistration;
import io.mosip.mimoto.model.DeviceRegistrationStatus;
import io.mosip.mimoto.repository.DeviceRegistrationRepository;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

import static io.mosip.mimoto.exception.ErrorConstants.DEVICE_NOT_REGISTERED;
import static io.mosip.mimoto.exception.ErrorConstants.DEVICE_REVOKED;
import static io.mosip.mimoto.exception.ErrorConstants.INVALID_DEVICE_PROOF;

/**
 * Verifies the device proof sent on get-token: a JWT signed by a registered device key with
 * header {@code typ=device-proof+jwt, alg=ES256, kid=<JWK thumbprint>} and claims
 * {@code nonce, htm, htu, iat, exp, req_hash}.
 * <p>
 * Freshness and single use come from the nonce issued by this mimoto; {@code exp - iat} must not exceed
 * {@code proof-max-age-seconds}, but neither is compared with the server clock, so device clock drift does not matter.
 * <p>
 * {@code htu} is compared by path only: mimoto sits behind an ingress whose public host it does not reliably know,
 * and the single-use nonce from this mimoto's bucket already prevents use against another server.
 * {@code req_hash} is base64url(SHA-256(raw request body)) and stops a proof being attached to a different request.
 */
@Service
public class DeviceProofVerifier {

    public static final JOSEObjectType PROOF_TYPE = new JOSEObjectType("device-proof+jwt");
    private static final Duration LAST_SEEN_INTERVAL = Duration.ofHours(1);

    private final DeviceRegistrationRepository repository;
    private final DeviceNonceService nonceService;
    private final Duration maxAge;
    private final Clock clock;

    @Autowired
    public DeviceProofVerifier(DeviceRegistrationRepository repository, DeviceNonceService nonceService,
                               DeviceAttestationProperties properties) {
        this(repository, nonceService, properties, Clock.systemUTC());
    }

    DeviceProofVerifier(DeviceRegistrationRepository repository, DeviceNonceService nonceService,
                        DeviceAttestationProperties properties, Clock clock) {
        this.repository = repository;
        this.nonceService = nonceService;
        this.maxAge = Duration.ofSeconds(properties.getProofMaxAgeSeconds());
        this.clock = clock;
    }

    /**
     * @return the JWK thumbprint of the device that signed the proof
     */
    public String verify(String proof, String method, String requestPath, byte[] body) {
        if (StringUtils.isBlank(proof)) {
            throw invalid("device proof is missing");
        }
        SignedJWT jwt;
        JWTClaimsSet claims;
        try {
            jwt = SignedJWT.parse(proof);
            claims = jwt.getJWTClaimsSet();
        } catch (Exception e) {
            throw invalid("device proof is not a signed JWT");
        }
        JWSHeader header = jwt.getHeader();
        if (!JWSAlgorithm.ES256.equals(header.getAlgorithm()) || !PROOF_TYPE.equals(header.getType())
                || StringUtils.isBlank(header.getKeyID())) {
            throw invalid("device proof header must have alg ES256, typ device-proof+jwt and a kid");
        }

        DeviceRegistration device = repository.findById(header.getKeyID())
                .orElseThrow(() -> new DeviceAttestationException(DEVICE_NOT_REGISTERED, "unknown device key " + header.getKeyID()));
        if (device.getStatus() != DeviceRegistrationStatus.ACTIVE) {
            throw new DeviceAttestationException(DEVICE_REVOKED, "device key is revoked");
        }
        try {
            if (!jwt.verify(new ECDSAVerifier(ECKey.parse(device.getPublicKeyJwk())))) {
                throw invalid("device proof signature is invalid");
            }
        } catch (DeviceAttestationException e) {
            throw e;
        } catch (Exception e) {
            throw invalid("device proof signature could not be verified");
        }

        Instant now = clock.instant();
        Date iat = claims.getIssueTime();
        Date exp = claims.getExpirationTime();
        if (iat == null || exp == null) {
            throw invalid("device proof must have iat and exp");
        }
        // Freshness comes from the single-use nonce, so iat and exp are not compared with this server's clock:
        // phones with a wrong clock would otherwise fail. Only the proof's own lifetime is bounded.
        if (!exp.toInstant().isAfter(iat.toInstant()) || exp.toInstant().isAfter(iat.toInstant().plus(maxAge))) {
            throw invalid("device proof lifetime is invalid");
        }
        if (!method.equalsIgnoreCase(stringClaim(claims, "htm"))) {
            throw invalid("device proof htm does not match");
        }
        if (!requestPath.equals(pathOf(stringClaim(claims, "htu")))) {
            throw invalid("device proof htu does not match");
        }
        if (!sha256(body).equals(stringClaim(claims, "req_hash"))) {
            throw invalid("device proof req_hash does not match the request body");
        }
        // Consumed last: a proof that fails any other check does not use up its nonce
        if (!nonceService.consume(stringClaim(claims, "nonce"))) {
            throw invalid("device proof nonce is unknown, expired or already used");
        }
        repository.touchLastSeen(device.getJwkThumbprint(), now, now.minus(LAST_SEEN_INTERVAL));
        return device.getJwkThumbprint();
    }

    private static String stringClaim(JWTClaimsSet claims, String name) {
        try {
            return StringUtils.defaultString(claims.getStringClaim(name));
        } catch (Exception e) {
            return "";
        }
    }

    private static String pathOf(String htu) {
        try {
            String path = URI.create(htu).getRawPath();
            return path == null ? "" : path;
        } catch (Exception e) {
            return "";
        }
    }

    static String sha256(byte[] body) {
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(body));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    private static DeviceAttestationException invalid(String detail) {
        return new DeviceAttestationException(INVALID_DEVICE_PROOF, detail);
    }
}
