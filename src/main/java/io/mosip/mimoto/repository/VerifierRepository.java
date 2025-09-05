package io.mosip.mimoto.repository;

import io.mosip.mimoto.model.TrustedVerifier;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface VerifierRepository extends JpaRepository<TrustedVerifier, String> {
    boolean existsByWalletIdAndVerifierId(String walletId, String verifierClientId);
}
