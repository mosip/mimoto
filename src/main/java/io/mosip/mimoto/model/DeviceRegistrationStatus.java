package io.mosip.mimoto.model;

public enum DeviceRegistrationStatus {
    // Device proofs signed by this key are accepted.
    ACTIVE,
    // Device proofs signed by this key are rejected. Re-registration does not reactivate it.
    REVOKED
}
