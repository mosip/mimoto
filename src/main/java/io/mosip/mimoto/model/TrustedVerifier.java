package io.mosip.mimoto.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "trusted_verifiers")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TrustedVerifier {

    @Id
    @Column(length = 36, updatable = false, nullable = false)
    private String id; // Primary Key

    @Column(name = "wallet_id", nullable = false)
    private String walletId; // Foreign key referencing wallets table

    @Column(name = "verifier_id", nullable = false, length = 255)
    private String verifierId; // Storing the verifier client ID

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt; // Time at which the user gave consent to accept the Verifier's request

    @PrePersist
    public void prePersist() {
        this.createdAt = Instant.now();
    }
}