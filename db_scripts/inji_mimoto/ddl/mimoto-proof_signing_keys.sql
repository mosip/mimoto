-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_mimoto
-- Table Name : proof_signing_key
-- Purpose    : Stores wallet key-related information, including encrypted secret keys and metadata
--
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- 2025-03-27          User                 Initial table creation, referencing wallet for proof_signing_key encryption
-- ------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS proof_signing_key (
    id character varying(36) PRIMARY KEY,  -- Primary key for the table
    wallet_id character varying(36) NOT NULL,  -- Foreign key referencing the wallet table
    public_key TEXT NOT NULL,  -- Public key for wallet
    secret_key TEXT NOT NULL,  -- Secret key, encrypted using proof_signing_key
    key_metadata JSONB NOT NULL,  -- Metadata about the public and private keys
    created_at TIMESTAMP DEFAULT now(),  -- Timestamp of record creation (defaults to current time)
    updated_at TIMESTAMP DEFAULT now(),  -- Timestamp of last update (defaults to current time)

    CONSTRAINT fk_wallet_id FOREIGN KEY (wallet_id) REFERENCES wallet (id) ON DELETE CASCADE
);

COMMENT ON TABLE proof_signing_key IS 'Wallet Keys: Contains information about the wallet keys, including encrypted keys and metadata';
COMMENT ON COLUMN proof_signing_key.id IS 'Primary Key: Unique identifier for the key';
COMMENT ON COLUMN proof_signing_key.wallet_id IS 'Wallet ID: Foreign key referring to the wallet table';
COMMENT ON COLUMN proof_signing_key.public_key IS 'Public Key: The public key of the wallet';
COMMENT ON COLUMN proof_signing_key.secret_key IS 'Secret Key: Encrypted using the proof_signing_key from wallet table';
COMMENT ON COLUMN proof_signing_key.key_metadata IS 'Key Metadata: Contains additional information about the public and private keys';
COMMENT ON COLUMN proof_signing_key.created_at IS 'Created At: The date and time when the key information was created';
COMMENT ON COLUMN proof_signing_key.updated_at IS 'Updated At: The date and time when the key information was last updated';