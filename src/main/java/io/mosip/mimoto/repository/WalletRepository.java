package io.mosip.mimoto.repository;

import io.mosip.mimoto.dbentity.Wallet;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface WalletRepository extends JpaRepository<Wallet, String> {
    @Query("SELECT w.id FROM Wallet w WHERE w.userId = :userId")
    List<UUID> findWalletIdByUserId(@Param("userId") UUID userId);

    Optional<Wallet> findByUserIdAndId(UUID userId, UUID walletId);
}
