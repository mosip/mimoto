package io.mosip.mimoto.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;

/**
 * Entity class for verifiable_presentations table
 */
@Entity
@Table(name = "verifiable_presentations")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class VerifiablePresentation {

    @Id
    @Column(name = "id", length = 255)
    private String id;

    @Column(name = "wallet_id", length = 255, nullable = false)
    private String walletId;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "auth_request", columnDefinition = "jsonb")
    private String authRequest;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "presentation_data", columnDefinition = "jsonb")
    private String presentationData;

    @Column(name = "verifier_id", length = 255)
    private String verifierId;

    @Column(name = "status", length = 50, nullable = false)
    private String status;

    @Column(name = "requested_at")
    private LocalDateTime requestedAt;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "consent", nullable = false)
    private Boolean consent;
}
