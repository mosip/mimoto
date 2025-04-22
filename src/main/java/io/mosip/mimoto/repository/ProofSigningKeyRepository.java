package io.mosip.mimoto.repository;

import io.mosip.mimoto.dbentity.ProofSigningKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface ProofSigningKeyRepository extends JpaRepository<ProofSigningKey, String> {
    @Query(value = "SELECT * FROM proof_signing_key p WHERE p.wallet_id = :walletId AND p.key_metadata->>'algorithmName' = :algorithmName", nativeQuery = true)
    Optional<ProofSigningKey> findByWalletIdAndAlgorithm(@Param("walletId") String walletId, @Param("algorithmName") String algorithmName);

    Optional<ProofSigningKey> findByWalletId(String walletId);
}