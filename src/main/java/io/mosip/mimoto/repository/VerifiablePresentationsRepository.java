package io.mosip.mimoto.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import io.mosip.mimoto.model.VerifiablePresentation;

/**
 * Repository interface for VerifiablePresentation entity
 */
@Repository
public interface VerifiablePresentationsRepository extends JpaRepository<VerifiablePresentation, String> {
    
}
