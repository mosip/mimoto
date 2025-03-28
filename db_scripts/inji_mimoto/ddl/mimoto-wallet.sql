-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_mimoto
-- Table Name : wallet
-- Purpose    : Wallet Information table for user, encrypted with AES256-GCM, including key metadata
--
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS wallet (
    id character varying(36) PRIMARY KEY,  -- Primary key for the table
    user_id character varying(36) NOT NULL,  -- Foreign key referencing user_metadata
    wallet_key TEXT NOT NULL,  -- Encrypted wallet key (retained here)
    wallet_metadata JSONB NOT NULL,  -- Metadata about the wallet, including encryption info
    created_at TIMESTAMP DEFAULT now(),  -- Timestamp of record creation (defaults to current time)
    updated_at TIMESTAMP DEFAULT now(),  -- Timestamp of last update (defaults to current time)

    CONSTRAINT fk_user_id FOREIGN KEY (user_id) REFERENCES user_metadata (id) ON DELETE CASCADE
);

COMMENT ON TABLE wallet IS 'Wallet: Contains general information about the user''s wallet and metadata';
COMMENT ON COLUMN wallet.id IS 'Primary Key: Unique identifier for the wallet';
COMMENT ON COLUMN wallet.user_id IS 'User ID: Foreign key referring to the user_metadata table';
COMMENT ON COLUMN wallet.wallet_key IS 'Wallet Key: Encrypted wallet key used to encrypt secret keys in wallet_keys';
COMMENT ON COLUMN wallet.wallet_metadata IS 'Wallet Metadata: Contains information about the wallet, including encryption and PIN usage';
COMMENT ON COLUMN wallet.created_at IS 'Created At: The date and time when the wallet was created';
COMMENT ON COLUMN wallet.updated_at IS 'Updated At: The date and time when the wallet was last updated';