package io.mosip.mimoto.repository;

import io.mosip.mimoto.dbentity.UserMetadata;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserMetadataRepository extends JpaRepository<UserMetadata, UUID> {
    Optional<UserMetadata> findByProviderSubjectId(String providerSubjectId);
}
