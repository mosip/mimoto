package io.mosip.mimoto.repository;

import io.mosip.mimoto.dbentity.VerifiableCredential;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface WalletCredentialsRepository extends JpaRepository<VerifiableCredential, String> {
    List<VerifiableCredential> findByWalletId(String walletId);
}
