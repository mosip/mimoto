-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_mimoto
-- Table Name : trusted_verifiers
-- Purpose    : Stores trusted verifiers associated with a user's wallet
--
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS trusted_verifiers (
    id character varying(36) PRIMARY KEY,  -- Primary key for the table
    wallet_id character varying(36) NOT NULL,  -- Foreign key referring to the wallet table (wallet.id)
    verifier_id character varying(36) NOT NULL,  -- Stores the unique identifier (client_id) of the trusted verifier
    created_at TIMESTAMP DEFAULT now()  -- Timestamp of record creation (defaults to current time)
);

COMMENT ON TABLE trusted_verifiers IS 'Trusted Verifiers: Contains information about verifiers trusted by a user''s wallet';

COMMENT ON COLUMN trusted_verifiers.id IS 'Primary Key: Unique identifier for the trusted verifier record';
COMMENT ON COLUMN trusted_verifiers.wallet_id IS 'Wallet ID: Foreign key referring to the wallet table, linking the verifier to a specific wallet';
COMMENT ON COLUMN trusted_verifiers.verifier_id IS 'Verifier ID: Unique identifier (client_id) of the trusted verifier';
COMMENT ON COLUMN trusted_verifiers.created_at IS 'Created At: The date and time when the trusted verifier record was created';