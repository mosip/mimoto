package io.mosip.mimoto.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.Map;

/**
 * A wallet device key registered after a successful platform attestation.
 * The key's RFC 7638 thumbprint identifies the device and is sent as the {@code kid} of every device proof.
 */
@Entity
@Table(name = "device_registration")
@Getter
@Setter
public class DeviceRegistration {

    @Id
    @Column(name = "jwk_thumbprint", length = 64, updatable = false, nullable = false)
    private String jwkThumbprint;

    @Enumerated(EnumType.STRING)
    @Column(length = 16, updatable = false, nullable = false)
    private DevicePlatform platform;

    @Column(name = "public_key_jwk", updatable = false, nullable = false)
    private String publicKeyJwk;

    @Enumerated(EnumType.STRING)
    @Column(length = 16, nullable = false)
    private DeviceRegistrationStatus status;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "attestation_verdict", columnDefinition = "jsonb")
    private Map<String, Object> attestationVerdict; // Verdict summary from the latest registration, kept for audit

    @Column(nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @Column(nullable = false)
    private Instant updatedAt = Instant.now();

    @Column
    private Instant lastSeenAt;

    @PreUpdate
    public void preUpdate() {
        this.updatedAt = Instant.now();
    }
}
