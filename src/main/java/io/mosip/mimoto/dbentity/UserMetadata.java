package io.mosip.mimoto.dbentity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import java.util.UUID;

@Entity
@Table(name = "user_metadata")
@Getter
@Setter
public class UserMetadata {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @Column(name = "provider_subject_id", nullable = false, unique = true)
    private String providerSubjectId;

    @Column(name = "identity_provider", nullable = false)
    private String identityProvider;

    @Column(name = "display_name", nullable = false)
    private String displayName;

    @Column(name = "profile_picture_url")
    private String profilePictureUrl;

    @Column(name = "phone_number")
    private String phoneNumber;

    @Column(name = "email", nullable = false)
    private String email;

    @Column(name = "created_at", updatable = false)
    private java.sql.Timestamp createdAt;

    @Column(name = "updated_at")
    private java.sql.Timestamp updatedAt;

    // Getters and Setters
}

