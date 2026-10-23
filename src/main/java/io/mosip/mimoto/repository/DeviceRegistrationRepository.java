package io.mosip.mimoto.repository;

import io.mosip.mimoto.model.DeviceRegistration;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Repository
public interface DeviceRegistrationRepository extends JpaRepository<DeviceRegistration, String> {

    /**
     * Records a device proof as seen, at most once per {@code threshold} window, so that
     * get-token calls do not write to the database on every request.
     *
     * @return number of rows updated (0 when the device was seen after {@code threshold})
     */
    @Modifying
    @Transactional
    @Query("UPDATE DeviceRegistration d SET d.lastSeenAt = :now WHERE d.jwkThumbprint = :thumbprint " +
            "AND (d.lastSeenAt IS NULL OR d.lastSeenAt < :threshold)")
    int touchLastSeen(@Param("thumbprint") String thumbprint, @Param("now") Instant now, @Param("threshold") Instant threshold);
}
