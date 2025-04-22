package io.mosip.mimoto.repository;

import io.mosip.mimoto.dbentity.Wallet;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface WalletRepository extends JpaRepository<Wallet, String> {
    @Query("SELECT w.id FROM Wallet w WHERE w.userId = :userId")
    List<String> findWalletIdByUserId(@Param("userId") String userId);

    Optional<Wallet> findByUserIdAndId(String userId, String walletId);
}
