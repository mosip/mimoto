-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_mimoto
-- Table Name : verifiable_credentials
-- Purpose    : Stores verifiable credentials related to the user, encrypted with wallet_key
--
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS verifiable_credentials (
    id UUID PRIMARY KEY,  -- Primary key for the table
    wallet_id UUID NOT NULL,  -- Foreign key referring to the wallet table (wallet.id)
    credential TEXT NOT NULL,  -- Encrypted credential (using wallet_key for encryption/decryption)
    credential_format VARCHAR(255) NOT NULL,  -- Format of the credential (e.g., JSON, JWT, etc.)
    credential_metadata JSON NOT NULL,  -- Metadata about the credential
    created_at TIMESTAMP DEFAULT now(),  -- Timestamp of record creation (defaults to current time)
    updated_at TIMESTAMP DEFAULT now(),  -- Timestamp of last update (defaults to current time)

    CONSTRAINT fk_wallet_id FOREIGN KEY (wallet_id) REFERENCES wallet (id) ON DELETE CASCADE
);

COMMENT ON TABLE verifiable_credentials IS 'Verifiable Credentials: Contains user credentials, encrypted using wallet key';
COMMENT ON COLUMN verifiable_credentials.id IS 'Primary Key: Unique identifier for the verifiable credential record';
COMMENT ON COLUMN verifiable_credentials.wallet_id IS 'Wallet ID: Foreign key referring to the wallet table, linked to the user''s wallet';
COMMENT ON COLUMN verifiable_credentials.credential IS 'Credential: Encrypted credential using the wallet''s key';
COMMENT ON COLUMN verifiable_credentials.credential_format IS 'Credential Format: Format of the credential (e.g., JSON, JWT)';
COMMENT ON COLUMN verifiable_credentials.credential_metadata IS 'Credential Metadata: Additional information about the credential (e.g., issuer, claims)';
COMMENT ON COLUMN verifiable_credentials.created_at IS 'Created At: The date and time when the credential was created';
COMMENT ON COLUMN verifiable_credentials.updated_at IS 'Updated At: The date and time when the credential was last updated';
