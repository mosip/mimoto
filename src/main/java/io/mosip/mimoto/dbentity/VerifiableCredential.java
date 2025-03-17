package io.mosip.mimoto.dbentity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import java.time.Instant;

@Entity
@Getter
@Setter
public class VerifiableCredential {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "wallet_id", nullable = false) // Foreign key reference to wallet table
    private Wallet wallet;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String credential; // Encrypted credential

    @Column(nullable = false, length = 255)
    private String credentialFormat; // Format of the credential (JSON, JWT, etc.)

    @Column(nullable = false, columnDefinition = "jsonb")
    private String credentialMetadata; // Additional metadata for the credential

    @Column(nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @Column(nullable = false)
    private Instant updatedAt = Instant.now();

    @PreUpdate
    public void preUpdate() {
        this.updatedAt = Instant.now();
    }
}
