-- Create table for device_registration
CREATE TABLE IF NOT EXISTS device_registration (
    jwk_thumbprint character varying(64) PRIMARY KEY,   -- RFC 7638 SHA-256 thumbprint of the device public key (base64url)
    platform character varying(16) NOT NULL,            -- Attestation platform: ANDROID/IOS
    public_key_jwk TEXT NOT NULL,                       -- Device public key as a JWK JSON string
    status character varying(16) NOT NULL,              -- Registration status: ACTIVE/REVOKED
    attestation_verdict JSONB,                          -- Summary of the attestation verdict from the latest registration
    created_at TIMESTAMP NOT NULL DEFAULT now(),        -- Timestamp of first registration
    updated_at TIMESTAMP NOT NULL DEFAULT now(),        -- Timestamp of the latest registration or status change
    last_seen_at TIMESTAMP                              -- Timestamp of the latest accepted device proof (updated at a throttled interval)
);

COMMENT ON TABLE device_registration IS 'Device Registration: Wallet device keys registered after a successful platform attestation';
COMMENT ON COLUMN device_registration.jwk_thumbprint IS 'JWK Thumbprint: RFC 7638 SHA-256 thumbprint of the device public key, used as the device proof kid';
COMMENT ON COLUMN device_registration.platform IS 'Platform: Attestation platform of the device (ANDROID/IOS)';
COMMENT ON COLUMN device_registration.public_key_jwk IS 'Public Key JWK: Device public key used to verify device proofs';
COMMENT ON COLUMN device_registration.status IS 'Status: ACTIVE/REVOKED; revoked devices are rejected and are not reactivated by re-registration';
COMMENT ON COLUMN device_registration.attestation_verdict IS 'Attestation Verdict: Summary of the verdict from the latest registration, kept for audit';
COMMENT ON COLUMN device_registration.created_at IS 'Created At: The date and time when the device was first registered';
COMMENT ON COLUMN device_registration.updated_at IS 'Updated At: The date and time of the latest registration or status change';
COMMENT ON COLUMN device_registration.last_seen_at IS 'Last Seen At: The date and time of the latest accepted device proof';
