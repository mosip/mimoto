package io.mosip.mimoto.repository;

import io.mosip.mimoto.model.UserMetadata;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface UserMetadataRepository extends JpaRepository<UserMetadata, String> {
    Optional<UserMetadata> findByProviderSubjectIdAndIdentityProvider(String providerSubjectId, String identityProvider);
}
