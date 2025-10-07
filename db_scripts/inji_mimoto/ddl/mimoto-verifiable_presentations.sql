-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_mimoto
-- Table Name : verifiable_presentations
-- Purpose    : Stores records of verifiable presentations submitted by a wallet to a verifier
--
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS verifiable_presentations (
    id character varying(36) PRIMARY KEY,               -- Primary key for the presentation record (use presentationId)
    wallet_id character varying(36) NOT NULL,           -- Foreign key referring to the wallet table (wallet.id)
    auth_request JSONB NOT NULL,                        -- Verifier's authorization request payload (as JSON)
    presentation_data JSONB NOT NULL,                   -- Additional metadata including shared credential ids
    verifier_id character varying(255),                 -- Verifier identifier (e.g., client_id)
    status character varying(32) NOT NULL,              -- Submission status: in-progress/success/error
    requested_at TIMESTAMP,                             -- Verifier request timestamp
    created_at TIMESTAMP DEFAULT now(),                 -- Submission timestamp (defaults to current time)
    consent BOOLEAN NOT NULL DEFAULT TRUE,              -- User consent flag

    CONSTRAINT fk_vp_wallet_id FOREIGN KEY (wallet_id) REFERENCES wallet (id) ON DELETE CASCADE
);

COMMENT ON TABLE verifiable_presentations IS 'Verifiable Presentations: Records of presentations shared with verifiers';
COMMENT ON COLUMN verifiable_presentations.id IS 'Primary Key: Unique identifier for the presentation (presentationId)';
COMMENT ON COLUMN verifiable_presentations.wallet_id IS 'Wallet ID: Foreign key referring to the wallet table';
COMMENT ON COLUMN verifiable_presentations.auth_request IS 'Authorization Request: The authorization request payload from the verifier';
COMMENT ON COLUMN verifiable_presentations.presentation_data IS 'Presentation Data: Additional metadata including shared credential ids';
COMMENT ON COLUMN verifiable_presentations.verifier_id IS 'Verifier Identifier: The verifier''s client_id or equivalent identifier';
COMMENT ON COLUMN verifiable_presentations.status IS 'Status: in-progress/success/error';
COMMENT ON COLUMN verifiable_presentations.requested_at IS 'Requested At: Timestamp when verifier requested the presentation';
COMMENT ON COLUMN verifiable_presentations.created_at IS 'Created At: Timestamp when the submission record was created';
COMMENT ON COLUMN verifiable_presentations.consent IS 'Consent: Indicates whether user consented to sharing';
