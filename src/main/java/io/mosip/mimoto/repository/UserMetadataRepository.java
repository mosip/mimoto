package io.mosip.mimoto.repository;

import io.mosip.mimoto.dbentity.UserMetadata;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface UserMetadataRepository extends JpaRepository<UserMetadata, String> {
    Optional<UserMetadata> findByProviderSubjectId(String providerSubjectId);
}
