package io.mosip.mimoto.dbentity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.UUID;

@Entity
@Getter
@Setter
public class Wallet {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @Column(nullable = false)
    private UUID userId; // Foreign key reference to user_metadata (long-based)

    @Column(nullable = false)
    private String walletKey; // Encrypted wallet key using AES256-GCM

    @Column(nullable = false)
    private String publicKey;

    @Column(nullable = false)
    private String secretKey; // Encrypted with walletKey

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private KeyMetadata keyMetadata;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private WalletMetadata walletMetadata;

    @Column(nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    @Column(nullable = false)
    private Instant updatedAt = Instant.now();

    @PreUpdate
    public void preUpdate() {
        this.updatedAt = Instant.now();
    }
}

