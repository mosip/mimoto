package io.mosip.mimoto.repository;

import io.mosip.mimoto.dbentity.VerifiableCredential;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;

@Repository
public interface WalletCredentialsRepository extends JpaRepository<VerifiableCredential, String> {
    List<VerifiableCredential> findByWalletId(String walletId);
    Optional<VerifiableCredential> findById(String id);

    @Query(value = "SELECT EXISTS (SELECT 1 FROM verifiable_credentials WHERE credential_metadata->>'issuerId' = :issuerId AND credential_metadata->>'credentialType' = :credentialType AND wallet_id = :walletId)", nativeQuery = true)
    boolean existsByIssuerIdAndCredentialTypeAndWalletId(@Param("issuerId") String issuerId, @Param("credentialType") String credentialType, @Param("walletId") String walletId);
}
