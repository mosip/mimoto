package io.mosip.mimoto.dbentity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.security.PrivateKey;
import java.time.Instant;

@Entity
@Getter
@Setter
public class ProofSigningKey {

    @Id
    @Column(length = 36, updatable = false, nullable = false)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "wallet_id", nullable = false)
    private Wallet wallet; // Foreign key reference to the wallet table

    @Column(nullable = false)
    private String publicKey; // Public key for wallet

    @Column(name = "secret_key", nullable = false)
    private String encryptedSecretKey; // Secret key, encrypted using walletKey

    @Transient
    private PrivateKey secretKey;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private KeyMetadata keyMetadata; // Metadata about the public and private keys

    @Column(nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @Column(nullable = false)
    private Instant updatedAt = Instant.now();

    @PreUpdate
    public void preUpdate() {
        this.updatedAt = Instant.now();
    }
}
